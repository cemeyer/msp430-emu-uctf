#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sysexits.h>
#include <unistd.h>

#include "emu.h"

// Only one client allowed to debug at a time...
int lsock = -1;
int csock = -1;

bool		 stepone;	// Single-step?
bool		 execute;	// Continue emu
GHashTable	*breakpoints;	// addr -> NULL

static void	 gdb_cmd(char *c, char *pound);

#define CMD_HANDLER(name) \
static void	 gdb_##name(const char *cmd, const void *extra)
CMD_HANDLER(getregs);
CMD_HANDLER(setregs);
CMD_HANDLER(readmem);
CMD_HANDLER(writemem);
CMD_HANDLER(addbreak);
CMD_HANDLER(rembreak);
CMD_HANDLER(conststring);
CMD_HANDLER(step);

static inline bool
streq(const char *s1, const char *s2)
{

	return strcmp(s1, s2) == 0;
}

static inline bool
startswith(const char *haystack, const char *prefix)
{

	return strncmp(haystack, prefix, strlen(prefix)) == 0;
}

static uint8_t
gdb_cksum(void *v, size_t len)
{
	uint8_t sum = 0, *s = v;

	for (; len && *s; s++, len--)
		sum += *s;

	return sum;
}

static uint8_t
gdb_cksumstr(void *s)
{

	return gdb_cksum(s, SIZE_MAX);
}

static void
gdb_sendraw(char *p, size_t len)
{
	ssize_t wr;

	ASSERT(csock != -1, "x");

	while (len) {
		wr = send(csock, p, len, 0);
		ASSERT(wr > 0, "send");

		len -= (unsigned)wr;
		p += (unsigned)wr;
	}
}

static inline void
gdb_sendrawstr(char *s)
{

	gdb_sendraw(s, strlen(s));
}

static void
gdb_sendstr(const char *s)
{
	unsigned chk, len;
	char buf[4096], *p;

	ASSERT(csock != -1, "csock");

	chk = gdb_cksumstr((void*)s);
	len = snprintf(buf, sizeof buf, "$%s#%02x", s, chk);

	gdb_sendraw(buf, len);
}

#define GDBSTUB_PORT 3713
static int
gdbstub_accept(void)
{
	int rc, flag, client;

	client = accept(lsock, NULL, NULL);
	if (client == -1)
		err(EX_OSERR, "accept");

	flag = 1;
	rc = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (void*)&flag,
	    sizeof flag);
	if (rc == -1)
		err(EX_OSERR, "setsockopt");

	rc = setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, (void*)&flag,
	    sizeof flag);
	if (rc == -1)
		err(EX_OSERR, "setsockopt");

	printf("GDB client connected.\n");
	return client;
}

void
gdbstub_init(void)
{
	int rc, optval;
	struct sockaddr_in any = { 0 };

	if (csock != -1)
		close(csock);
	csock = -1;
	if (lsock != -1)
		close(lsock);
	lsock = -1;

	lsock = socket(AF_INET, SOCK_STREAM, 0);
	if (lsock == -1)
		err(EX_OSERR, "socket");

	optval = 1;
	rc = setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof
	    optval);
	if (rc == -1)
		err(EX_OSERR, "setsockopt(REUSEADDR)");

	any.sin_family = PF_INET;
	any.sin_port = htons(GDBSTUB_PORT);
	any.sin_addr.s_addr = htonl(INADDR_ANY);

	rc = bind(lsock, (void*)&any, sizeof any);
	if (rc == -1)
		err(EX_OSERR, "bind");

	rc = listen(lsock, 20);
	if (rc == -1)
		err(EX_OSERR, "listen");

	printf("GDB stub listening on [*]:%u\n", (uns)GDBSTUB_PORT);

	printf("Waiting for client to connect...\n");
	csock = gdbstub_accept();
	ASSERT(csock != -1, "gdbstub_accept");

	breakpoints = g_hash_table_new(NULL, NULL);

	// Go to interactive before executing first instruction.
	stepone = true;
}

// Called when emulator is stopped, awaiting remote commands. (Including
// initial state.)
char clientbuf[8192];
size_t cblen;

void
gdbstub_interactive(void)
{
	bool processed_any = true;
	char *bp, *ep;
	ssize_t rd;
	int rc;

	execute = false;
	ASSERT(csock != -1, "x");

	do {
		if (!processed_any) {
			struct pollfd pfd = { 0 };

			pfd.fd = csock;
			pfd.events = POLLIN;
			rc = poll(&pfd, 1, -1);

			ASSERT(rc >= 0, "poll: %s", strerror(errno));
		}

		rd = recv(csock, &clientbuf[cblen], sizeof clientbuf - cblen,
		    MSG_DONTWAIT);
		if (rd == 0) {
			printf("Client dropped, exiting.\n");
			exit(0);
		}

		if (rd < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				err(1, "recv");
			goto process;
		}

		cblen += (size_t)rd;

process:
		processed_any = false;
		bp = clientbuf;
		ep = &clientbuf[cblen];
		// We have cblen valid bytes of protocol at p.
		// Process as many full packets as possible...
		while (bp < ep) {
			char *pound;

			if (*bp == '+' || *bp == '-') {
				bp++;
				cblen--;
				processed_any = true;
				continue;
			}

			pound = memchr(bp, '#', ep - bp);
			if (pound && (pound + 2) < ep) {
				gdb_cmd(bp, pound);

				processed_any = true;
				bp = pound + 3;

				if (execute)
					break;
			}
		}

		if (bp != clientbuf) {
			cblen = ep - bp;
			memmove(clientbuf, bp, cblen);
		}
	} while (!execute);

	ASSERT(execute,
	    "we shouldn't leave GDB interactive until we are told to");
}

struct cmd_dispatch {
	const char	 *cmd,
			 *extra;
	void		(*handler)(const char *cmd, const void *extra);
	bool		  continue_exec;
};

static struct cmd_dispatch gdb_disp[] = {
	{ "g" /* fetch reGisters */, NULL, gdb_getregs, false, },
	{ "G" /* set reGisters */, NULL, gdb_setregs, false, },
	{ "m" /* read Memory */, NULL, gdb_readmem, false, },
	{ "M" /* write Memory */, NULL, gdb_writemem, false, },
	{ "Z0" /* break */, NULL, gdb_addbreak, false, },
	{ "z0" /* unbreak */, NULL, gdb_rembreak, false, },
	{ "qAttached" /* initial attach */, "1", gdb_conststring, false, },
	{ "?" /* wat */, "S05", gdb_conststring, false, },
	{ "Hg" /* ??? */, "OK", gdb_conststring, false, },
	{ "Hc" /* ??? */, "OK", gdb_conststring, false, },
	{ "c" /* Continue */, NULL, NULL, true, },
	{ "s" /* Step */, NULL, gdb_step, true, },
	{ 0 },
};


static void
gdb_cmd(char *c, char *pound)
{
	unsigned ckcalc, cksend;
	bool dispatched;
	int rc;

	ASSERT(*c != '+' && *c != '-', "should have been slurped already");

	ckcalc = gdb_cksum(c+1, pound - c - 1);
	rc = sscanf(pound, "#%2x", &cksend);
	ASSERT(rc == 1, "proto");

	if (ckcalc != cksend) {
		gdb_sendrawstr("-");	// NAK
		return;
	}

	gdb_sendrawstr("+");	// ACK
	*pound = 0;

	if (*c != '$') {
		printf("XXX Got weird cmd: '%s'\n", c);
		gdb_sendstr("");
		return;
	}
	c++;

	dispatched = false;
	for (struct cmd_dispatch *d = gdb_disp; d->cmd; d++) {
		if (startswith(c, d->cmd)) {
			if (d->handler)
				d->handler(c, d->extra);
			dispatched = true;
			execute = d->continue_exec;
			break;
		}
	}

	if (!dispatched) {
		printf("XXX Got unhandled $cmd: '%s'\n", c);
		gdb_sendstr("");
		return;
	}
}

// Called once per instruction
void
gdbstub_intr(void)
{
	int rc;
	bool interact = false;

	if (csock == -1)
		return;

	if (stepone) {
		interact = true;
		stepone = false;
	} else if (g_hash_table_contains(breakpoints, ptr(registers[PC]))) {
		printf("Breakpoint @%04x\n", (uns)registers[PC]);
		interact = true;
		gdbstub_breakpoint();
	}

	// XXX IF we broke, or single-stepped after previous request, then we
	// need to return control to GDB.
	if (interact)
		gdbstub_interactive();

	// Anything else we need to watch on a per-instruction basis?
}

void
gdbstub_breakpoint(void)
{

	ASSERT(csock != -1, "x");
	gdb_sendstr("S05" /* trap */);
}

// Called when the program halts.
void
gdbstub_stopped(void)
{

	if (csock == -1)
		return;

	close(csock);
	csock = -1;
}

// char* cmd, void* extra
CMD_HANDLER(getregs)
{
	char buf[16*4+1];
	int rc;

	(void)cmd;
	(void)extra;

	for (unsigned i = 0; i < 16; i++) {
		rc = sprintf(&buf[i*4], "%02x%02x", registers[i] & 0xff,
		    registers[i] >> 8);
		ASSERT(rc == 4, "x");
	}

	gdb_sendstr(buf);
}

CMD_HANDLER(setregs)
{
	unsigned reglo, reghi, i;
	int rc;

	(void)extra;

	cmd++;
	for (i = 0; i < 16; i++) {
		ASSERT(*cmd, "x");

		rc = sscanf(cmd, "%02x%02x", &reglo, &reghi);
		ASSERT(rc == 2, "x");

		registers[i] = reglo | (reghi << 8);
		cmd += 4;
	}

	gdb_sendstr("OK");
}

// Read/write memory as a stream of bytes
CMD_HANDLER(readmem)
{
	unsigned start, rlen, slen, i;
	char buffer[4096+1] = { 0 };
	int rc;

	(void)extra;

	cmd++;
	rc = sscanf(cmd, "%x,%x", &start, &rlen);
	ASSERT(rc == 2, "x");

	ASSERT(rlen*2 < sizeof buffer, "buffer overrun");
	slen = 0;
	for (i = 0; i < rlen; i++) {
		rc = sprintf(&buffer[slen], "%02x", membyte(start + i));

		ASSERT(rc == 2, "x");
		slen += (unsigned)rc;
	}

	gdb_sendstr(buffer);
}

CMD_HANDLER(writemem)
{
	unsigned start, len, byte;
	const char *hexs;
	int rc, hex;

	(void)extra;

	cmd++;
	hex = 0;

	rc = sscanf(cmd, "%x,%x:%n", &start, &len, &hex);
	ASSERT(rc == 2 || rc == 3, "x");

	if (hex == 0) {
		printf("ill-formed write: %s\n", cmd);
		exit(1);
	}

	hexs = cmd + hex;

	for (unsigned i = 0; i < len; i++) {
		rc = sscanf(hexs + 2*i, "%02x", &byte);
		ASSERT(rc == 1, "x");

		memory[(start + i) & 0xffff] = byte;
	}

	gdb_sendstr("OK");
}

CMD_HANDLER(addbreak)
{
	int rc;
	unsigned addr;

	(void)extra;

	cmd += strlen("Z0");
	rc = sscanf(cmd, ",%x", &addr);
	ASSERT(rc == 1, "x");

	g_hash_table_insert(breakpoints, ptr(addr), NULL);

	gdb_sendstr("OK");
}

CMD_HANDLER(rembreak)
{
	int rc;
	unsigned addr;

	(void)extra;

	cmd += strlen("z0");
	rc = sscanf(cmd, ",%x", &addr);
	ASSERT(rc == 1, "x");

	g_hash_table_remove(breakpoints, ptr(addr));

	gdb_sendstr("OK");
}

CMD_HANDLER(conststring)
{

	(void)cmd;
	gdb_sendstr(extra);
}

CMD_HANDLER(step)
{

	(void)cmd;
	(void)extra;

	stepone = true;
	gdb_sendstr("S05");
}
