#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sysexits.h>
#include <unistd.h>

#include "emu.h"

// Only one client allowed to debug at a time...
int lsock = -1;
int csock = -1;

bool no_ack,
     no_ack_test;

GHashTable	*breakpoints;	// addr -> NULL

static void	 gdb_cmd(char *c, char *pound);

static uint8_t
gdb_cksum(uint8_t *s)
{
	uint8_t sum = 0;

	for (; *s; s++)
		sum += *s;

	return sum;
}

static void
gdb_sendstr(char *s)
{
	unsigned chk, len;
	char buf[4096], *p;
	ssize_t wr;

	ASSERT(csock != -1, "csock");

	chk = gdb_cksum((void*)s);
	len = snprintf(buf, sizeof buf, "$%s#%02x", s, chk);

	for (p = buf; len;) {
		wr = send(csock, p, len, 0);
		ASSERT(wr > 0, "send");

		len -= (unsigned)wr;
		p += (unsigned)wr;
	}
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
	gdbstub_interactive();
}

// Called when emulator is stopped, awaiting remote commands. (Including
// initial state.)
char clientbuf[8192];
size_t cblen;

void
gdbstub_interactive(void)
{
	bool processed_any = false;
	char *bp, *ep;
	ssize_t rd;

	ASSERT(csock != -1, "x");

	do {
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
			}
			break;
		}

		if (bp != clientbuf) {
			cblen = ep - bp;
			memmove(clientbuf, bp, cblen);
		}
	} while (processed_any);
}

static void
gdb_cmd(char *c, char *pound)
{

	// TODO FLESH THIS OUT.
	printf("XXX Got cmd: %s\n", c);
	exit(0);
}

// Called once per instruction
void
gdbstub_intr(void)
{
	int flag, rc;

	if (csock == -1)
		return;

	if (g_hash_table_contains(breakpoints, ptr(registers[PC]))) {
		printf("Breakpoint @%04x\n", (uns)registers[PC]);
		gdbstub_breakpoint();

		// XXX We may need to transmit something:
		// microlathe:
		// send('T%02x%s:%s;thread:1;' % (sig, 'pc', swapb('%.4x' % pc)))
		// gdbstub_interactive();
	}

	// Anything else we need to watch on a per-instruction basis?

	// Have client? Process all available commands, check for breakpoints,
	// yada yada.
}

void
gdbstub_breakpoint(void)
{

	ASSERT(csock != -1, "x");
	gdb_sendstr("S05");	// TODO: What is S05?
}

// Called when the program halts.
void
gdbstub_stopped(void)
{

	if (csock == -1)
		return;

	//YYY;
}
