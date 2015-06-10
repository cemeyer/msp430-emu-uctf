#include <unistd.h>

#include "emu.h"

struct inprec {
	uint64_t	 ir_insn;
	size_t		 ir_len;
	char		 ir_inp[0];
};

uint16_t	 pc_start,
		 instr_size;
uint8_t		 pageprot[0x100];
uint16_t	 registers[16];
uint8_t		 memory[0x10000];
#if SYMBOLIC
struct sexp	*register_symbols[16];
GHashTable	*memory_symbols;		// addr -> sexp*
#endif
uint64_t	 start;
uint64_t	 insns;
uint64_t	 insnlimit;
uint64_t	 insnreplaylim;
uint16_t	 syminplen;
bool		 off;
bool		 unlocked;
bool		 dep_enabled;
bool		 replay_mode;
bool		 ctrlc;

bool		 tracehex;
FILE		*tracefile;

GHashTable	*input_record;			// insns -> inprec

static bool	 diverged;

#if SYMBOLIC
static struct sexp SEXP_0 = {.s_kind = S_IMMEDIATE, .s_nargs = 0},
		   SEXP_1 = {.s_kind = S_IMMEDIATE, .s_nargs = 1},
		   SEXP_8 = {.s_kind = S_IMMEDIATE, .s_nargs = 8},
		   SEXP_FF00 = {.s_kind = S_IMMEDIATE, .s_nargs = 0xff00},
		   SEXP_00FF = {.s_kind = S_IMMEDIATE, .s_nargs = 0x00ff},
		   SEXP_NEG_1 = {.s_kind = S_IMMEDIATE, .s_nargs = 0xffff};
#endif

// Fast random numbers:
// 18:16 < rmmh> int k = 0x123456; int rand() { k=30903*(k&65535)+(k>>16);
//               return(k&65535); }

#if SYMBOLIC
static struct sexp *
bytemask(struct sexp *s)
{
	struct sexp *t = sexp_alloc(S_AND);

	t->s_nargs = 2;
	t->s_arg[0] = s;
	t->s_arg[1] = sexp_imm_alloc(0xff);
	return t;
}

struct sexp *
mksexp(enum sexp_kind sk, unsigned nargs, ...)
{
	struct sexp *t = sexp_alloc(sk);
	va_list ap;

	ASSERT(nargs <= SEXP_MAXARGS, "xx");
	ASSERT(sk != S_INP && sk != S_IMMEDIATE, "xx");
	t->s_nargs = nargs;

	va_start(ap, nargs);
	for (unsigned i = 0; i < nargs; i++) {
		struct sexp *a = va_arg(ap, struct sexp *);

		ASSERT((uintptr_t)a > 0x10000, "non-null, non-number");

		t->s_arg[i] = a;
	}
	va_end(ap);

	return t;
}
#endif

void
print_ips(void)
{
	uint64_t end = now();

	if (end == start)
		end++;

	printf("Approx. %ju instructions per second (Total: %ju).\n",
	    (uintmax_t)insns * 1000000 / (end - start), (uintmax_t)insns);
}

void
init(void)
{

	insns = 0;
	off = unlocked = false;
	start = now();
	//memset(memory, 0, sizeof(memory));
	memset(registers, 0, sizeof registers);
	memset(pageprot, DEP_R|DEP_W|DEP_X, sizeof pageprot);
	dep_enabled = false;
#if SYMBOLIC
	memory_symbols = g_hash_table_new(NULL, NULL);
	ASSERT(memory_symbols, "g_hash");

	for (unsigned reg = 0; reg < 16; reg++)
		register_symbols[reg] = NULL;
#endif
}

void
destroy(void)
{

#if SYMBOLIC
	ASSERT(memory_symbols, "mem_symbol_hash");
	g_hash_table_destroy(memory_symbols);
	memory_symbols = NULL;

	for (unsigned reg = 0; reg < 16; reg++) {
		if (isregsym(reg))
			free(regsym(reg));
		register_symbols[reg] = NULL;
	}
#endif
}

#ifndef EMU_CHECK
static void
ctrlc_handler(int s)
{

	(void)s;
	ctrlc = true;
}

void
usage(void)
{
#if SYMBOLIC
	printf("usage: msp430-sym [binaryimage] [sym-inp-len]\n");
#else
	printf("usage: msp430-emu FLAGS [binaryimage]\n"
		"\n"
		"  FLAGS:\n"
		"    -g            Debug with GDB\n"
		"    -t=TRACEFILE  Emit instruction trace\n"
		"    -x            Trace output in hex\n");
#endif
		exit(1);
}

int
main(int argc, char **argv)
{
	size_t rd, idx;
	const char *romfname;
	FILE *romfile;
	int opt;
	bool waitgdb = false;

#if SYMBOLIC
	if (argc < 3)
#else
	if (argc < 2)
#endif
		usage();

#if SYMBOLIC
	romfname = argv[1];
#else
	while ((opt = getopt(argc, argv, "gt:x")) != -1) {
		switch (opt) {
		case 'g':
			waitgdb = true;
			break;
		case 't':
			tracefile = fopen(optarg, "wb");
			if (!tracefile) {
				printf("Failed to open tracefile `%s'\n",
				    optarg);
				exit(1);
			}
			break;
		case 'x':
			tracehex = true;
			break;
		default:
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();

	romfname = argv[optind];
#endif

	romfile = fopen(romfname, "rb");
	ASSERT(romfile, "fopen");

#if SYMBOLIC
	syminplen = atoll(argv[2]);
#endif

	input_record = g_hash_table_new_full(NULL, NULL, NULL, free);
	ASSERT(input_record, "x");

	init();

	idx = 0;
	while (true) {
		rd = fread(&memory[idx], 1, sizeof(memory) - idx, romfile);
		if (rd == 0)
			break;
		idx += rd;
	}
	printf("Loaded %zu words from image.\n", idx/2);
	memwriteword(0x10, 0x4130); // callgate

	fclose(romfile);

	signal(SIGINT, ctrlc_handler);

	registers[PC] = memword(0xfffe);

	if (waitgdb)
		gdbstub_init();

	emulate();

	printf("Got CPUOFF, stopped.\n");
	gdbstub_stopped();

	print_regs();
	print_ips();

	if (tracefile)
		fclose(tracefile);

	return 0;
}
#endif

#if SYMBOLIC
static bool
sexpdepth(struct sexp *s, unsigned max)
{

	if (max == 0)
		return true;

	if (s->s_kind == S_INP || s->s_kind == S_IMMEDIATE)
		return false;

	for (unsigned i = 0; i < s->s_nargs; i++)
		if (sexpdepth(s->s_arg[i], max - 1))
			return true;

	return false;
}
#endif

void
emulate1(void)
{
	uint16_t instr;

	pc_start = registers[PC];
	instr_size = 2;

#ifdef BF
	if (registers[PC] & 0x1) {
		//printf("insn addr unaligned");
		off = true;
		return;
	}
#else
	ASSERT((registers[PC] & 0x1) == 0, "insn addr unaligned");
#endif

	depcheck(registers[PC], DEP_X);
	instr = memword(registers[PC]);

	// dec r15; jnz -2 busy loop
	if ((instr == 0x831f || instr == 0x533f) &&
	    memword(registers[PC]+2) == 0x23fe) {
#if SYMBOLIC
		ASSERT(!isregsym(15), "TODO");
#endif
		//insns += (2ul * registers[15]) + 1;
		registers[15] = 0;

#if SYMBOLIC
		ASSERT(!isregsym(SR), "TODO");
#endif
		registers[SR] &= ~(SR_C | SR_N | SR_V);
		registers[SR] |= SR_Z;
		registers[PC] += 4;
		goto out;
	}

	switch (bits(instr, 15, 13)) {
	case 0:
		handle_single(instr);
		break;
	case 0x2000:
		handle_jump(instr);
		break;
	default:
		handle_double(instr);
		break;
	}

#if SYMBOLIC
	for (unsigned i = 0; i < 16; i++) {
		if (!isregsym(i))
			continue;

		// concretify
		if (regsym(i)->s_kind == S_IMMEDIATE) {
			registers[i] = regsym(i)->s_nargs;
			register_symbols[i] = NULL;
			continue;
		}

		// depth=12 -> only uses first 6 bytes
		// depth=11 -> only uses first 4?
#if 0
		if (sexpdepth(regsym(i), 7)) {
			printf("r%d is *too* symbolic:\n", i);
			printsym(regsym(i));
			printf("/r%d\n", i);
			print_regs();
			off = true;
		}
#endif
	}
#endif

	if (!replay_mode && tracefile) {
		ASSERT((instr_size / 2) > 0 && (instr_size / 2) < 4,
		    "instr_size: %d", instr_size);

		for (unsigned i = 0; i < instr_size; i += 2) {
			if (tracehex)
				fprintf(tracefile, "%02x%02x ",
				    (uns)membyte(pc_start+i),
				    (uns)membyte(pc_start+i+1));
			else {
				size_t wr;
				wr = fwrite(&memory[(pc_start + i) & 0xffff],
				    2, 1, tracefile);
				ASSERT(wr == 1, "fwrite: %s", strerror(errno));
			}
		}

		if (tracehex)
			fprintf(tracefile, "\n");
	}

out:
	insns++;
}

static void
dumpmem(uint16_t addr, unsigned len)
{

	for (unsigned i = 0; i < len; i++) {
		printf("%02x", membyte(addr+i));
		if (i % 0x10 == 0xf)
			printf("\n");
	}
}

void
emulate(void)
{

#ifndef QUIET
	printf("Initial register state:\n");
	print_regs();
	printf("============================================\n\n");
#endif

	while (true) {
		if (ctrlc) {
			printf("Got ^C, stopping...\n");
			abort_nodump();
		}

#if SYMBOLIC
		if (isregsym(PC)) {
			printf("symbolic PC\n");
			abort_nodump();
		}
#endif

#ifndef EMU_CHECK
		if (replay_mode && insns >= insnreplaylim) {
			replay_mode = false;
			insnreplaylim = 0;
			// return control to remote GDB
			stepone = true;
		}

		if (!replay_mode)
			gdbstub_intr();

		if (replay_mode && insnreplaylim < insns) {
			init();
			registers[PC] = memword(0xfffe);
			continue;
		}
#endif

		if (registers[PC] == 0x0010) {
#if SYMBOLIC
			if (isregsym(SR)) {
				printf("Symbolic interrupt!!!\nSR =>");
				printsym(regsym(SR));
				abort_nodump();
			}
#endif

			// Callgate
			if (registers[SR] & 0x8000) {
				unsigned op = (registers[SR] >> 8) & 0x7f;
				callgate(op);
			}
		}

		if (off)
			break;

		emulate1();

#if SYMBOLIC
		ASSERT(!isregsym(CG), "CG symbolic");
#endif
		ASSERT(registers[CG] == 0, "CG");
		if (off || registers[SR] & SR_CPUOFF) {
			off = true;
			break;
		}

		if (insnlimit && insns >= insnlimit) {
#ifndef BF
			printf("\nXXX Hit insn limit, halting XXX\n");
#endif
			break;
		}
	}
}

void
inc_reg(uint16_t reg, uint16_t bw)
{
	uint16_t inc = 2;

	if (reg != PC && reg != SP && bw)
		inc = 1;

#if SYMBOLIC
	ASSERT(!isregsym(reg), "symbolic reg(%u): can't inc", (uns)reg);
#endif
	registers[reg] = (registers[reg] + inc) & 0xffff;
}

void
dec_reg(uint16_t reg, uint16_t bw)
{
	uint16_t inc = 2;

	if (reg != PC && reg != SP && bw)
		inc = 1;

#if SYMBOLIC
	ASSERT(!isregsym(reg), "symbolic reg(%u): can't dec", (uns)reg);
#endif
	registers[reg] = (registers[reg] - inc) & 0xffff;
}

void
handle_jump(uint16_t instr)
{
	uint16_t cnd = bits(instr, 12, 10) >> 10,
		 offset = bits(instr, 9, 0);
	bool shouldjump = false;

	// sign-extend
	if (offset & 0x200)
		offset |= 0xfc00;

	// double
	offset = (offset << 1) & 0xffff;

	inc_reg(PC, 0);

#if SYMBOLIC
	if (cnd != 0x7 && isregsym(SR)) {
		printf("XXX symbolic branch\nSR: ");
		printsym(regsym(SR));
		abort_nodump();
	}
#endif

	switch (cnd) {
	case 0x0:
		// JNZ
		if ((registers[SR] & SR_Z) == 0)
			shouldjump = true;
		break;
	case 0x1:
		// JZ
		if (registers[SR] & SR_Z)
			shouldjump = true;
		break;
	case 0x2:
		// JNC
		if ((registers[SR] & SR_C) == 0)
			shouldjump = true;
		break;
	case 0x3:
		// JC
		if (registers[SR] & SR_C)
			shouldjump = true;
		break;
	case 0x4:
		// JN
		if (registers[SR] & SR_N)
			shouldjump = true;
		break;
	case 0x5:
		// JGE
		{
		bool N = !!(registers[SR] & SR_N),
		     V = !!(registers[SR] & SR_V);
		shouldjump = ((N ^ V) == 0);
		}
		break;
	case 0x6:
		// JL
		{
		bool N = !!(registers[SR] & SR_N),
		     V = !!(registers[SR] & SR_V);
		shouldjump = (N ^ V);
		}
		break;
	case 0x7:
		// JMP
		shouldjump = true;
		break;
	default:
		unhandled(instr);
		break;
	}

	if (shouldjump)
		registers[PC] = (registers[PC] + offset) & 0xffff;
}

void
handle_single(uint16_t instr)
{
	enum operand_kind srckind, dstkind;
	uint16_t constbits = bits(instr, 12, 10) >> 10,
		 bw = bits(instr, 6, 6),
		 As = bits(instr, 5, 4),
		 dsrc = bits(instr, 3, 0),
		 srcval, srcnum = 0, dstval;
	unsigned res = (uns)-1;
	uint16_t setflags = 0,
		 clrflags = 0;
#if SYMBOLIC
	struct sexp *srcsym = NULL, *ressym = NULL, *flagsym = NULL;
#endif

	inc_reg(PC, 0);

	// Bogus initialization for GCC
	srcval = 0xffff;
	srckind = OP_FLAGSONLY;

	load_src(instr, dsrc, As, bw, &srcval, &srckind);

	if (off)
		return;

	dstkind = srckind;
	dstval = srcval;

	// Load addressed src values
	switch (srckind) {
	case OP_REG:
#if SYMBOLIC
		if (isregsym(srcval))
			srcsym = regsym(srcval);
		else
#endif
			srcnum = registers[srcval];
		break;
	case OP_MEM:
#if SYMBOLIC
		if (ismemsym(srcval, bw))
			srcsym = memsym(srcval, bw);
		else {
#endif
			if (bw)
				srcnum = membyte(srcval);
			else
				srcnum = memword(srcval);
#if SYMBOLIC
		}
#endif
		break;
	case OP_CONST:
		srcnum = srcval;
		break;
	default:
		ASSERT(false, "illins");
		break;
	}

	// '0x0000' is an illegal instruction, but #uctf ignores bits 0x1800 in
	// single-op instructions. We'll do it just for zero, trap on
	// everything else...
	if (constbits != 0x4 && instr != 0x0 && instr != 0x03)
		illins(instr);

	switch (bits(instr, 9, 7)) {
	case 0x000:
		// RRC
#if SYMBOLIC
		if (srcsym) {
			if (bw)
				srcsym = peephole(bytemask(srcsym));
			ressym = mksexp(S_RSHIFT, 2, srcsym, &SEXP_1);
			flagsym = mksexp(S_SR_RRC, 1, peephole(ressym));
		} else {
#endif
			if (bw)
				srcnum &= 0xff;
			res = srcnum >> 1;

#if SYMBOLIC
			ASSERT(!isregsym(SR), "TODO");
#endif
			if (registers[SR] & SR_C) {
				if (bw)
					res |= 0x80;
				else
					res |= 0x8000;
			}

			if (srcnum & 0x1)
				setflags |= SR_C;
			else
				clrflags |= SR_C;
			if (res & 0x8000)
				setflags |= SR_N;
			// doesn't clear N
			if (res)
				clrflags |= SR_Z;
			// doesn't set Z
#if SYMBOLIC
		}
#endif
		break;
	case 0x080:
		// SWPB (no flags)
#if SYMBOLIC
		if (srcsym) {
			struct sexp *lo, *hi;

			hi = mksexp(S_LSHIFT, 2, bytemask(srcsym), &SEXP_8);
			lo = mksexp(S_RSHIFT, 2, srcsym, &SEXP_8);

			ressym = mksexp(S_OR, 2, hi, lo);
		} else
#endif
			res = ((srcnum & 0xff) << 8) | (srcnum >> 8);
		break;
	case 0x100:
		// RRA (flags)
#if SYMBOLIC
		if (srcsym) {
			if (bw)
				srcsym = peephole(bytemask(srcsym));
			ressym = mksexp(S_RRA, 2, srcsym, &SEXP_1);
			flagsym = mksexp(S_SR_RRA, 1, ressym);
		} else {
#endif
			if (bw)
				srcnum &= 0xff;
			res = srcnum >> 1;
			if (bw && (0x80 & srcnum))
				res |= 0x80;
			else if (bw == 0 && (0x8000 & srcnum))
				res |= 0x8000;

			clrflags |= SR_Z;
			if (0x8000 & res)
				setflags |= SR_N;
#if SYMBOLIC
		}
#endif
		break;
	case 0x180:
		// SXT (sets flags)
#if SYMBOLIC
		if (srcsym) {
			ressym = mksexp(S_SXT, 1, peephole(mksexp(S_AND, 2,
				    srcsym, &SEXP_00FF)));
			flagsym = mksexp(S_SR_AND, 1, ressym);
		} else {
#endif
			if (srcnum & 0x80)
				res = srcnum | 0xff00;
			else
				res = srcnum & 0x00ff;

			andflags(res, &setflags, &clrflags);
#if SYMBOLIC
		}
#endif
		break;
	case 0x200:
		// PUSH (no flags)
		dec_reg(SP, 0);
		dstval = registers[SP];
		dstkind = OP_MEM;

#if SYMBOLIC
		if (srcsym)
			ressym = srcsym;
		else
#endif
			res = srcnum;
		break;
	case 0x280:
		// CALL (no flags)
#if SYMBOLIC
		if (srcsym) {
			printf("XXX symbolic CALL\n");
			abort_nodump();
		} else {
#endif
			// Call [src]
			res = srcnum;
			dstval = PC;
			dstkind = OP_REG;

			// Push PC+1
			dec_reg(SP, 0);
			memwriteword(registers[SP], registers[PC]);
#if SYMBOLIC
		}
#endif
		break;
	default:
		unhandled(instr);
		break;
	}

#if SYMBOLIC
	// concretify
	if (ressym && ressym->s_kind == S_IMMEDIATE) {
		res = ressym->s_nargs & 0xffff;
		sexp_flags(flagsym, &setflags, &clrflags);
		ressym = NULL;
	}

	if (ressym) {
		if (flagsym)
			register_symbols[SR] = peephole(flagsym);

		if (dstkind == OP_REG)
			register_symbols[dstval] = peephole(ressym);
		else if (dstkind == OP_MEM)
			memwritesym(dstval, bw, peephole(ressym));
		else
			ASSERT(dstkind == OP_FLAGSONLY, "x");
	} else {
#endif
		if (setflags || clrflags) {
			ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
#if SYMBOLIC
			if (isregsym(SR)) {
				struct sexp *s = sexp_alloc(S_OR), *t;
				s->s_nargs = 2;
				s->s_arg[0] = regsym(SR);
				s->s_arg[1] = sexp_imm_alloc(setflags);
				t = sexp_alloc(S_AND);
				t->s_nargs = 2;
				t->s_arg[0] = s;
				t->s_arg[1] = sexp_imm_alloc(~clrflags & 0x1ff);
				register_symbols[SR] = peephole(t);
			} else {
#endif
				registers[SR] |= setflags;
				registers[SR] &= ~clrflags;
				registers[SR] &= 0x1ff;
#if SYMBOLIC
			}
#endif
		}

		if (dstkind == OP_REG) {
			ASSERT(res != (uns)-1, "res never set");

			if (bw)
				res &= 0x00ff;

#if SYMBOLIC
			if (isregsym(dstval))
				register_symbols[dstval] = NULL;
#endif

			if (dstval != CG)
				registers[dstval] = res & 0xffff;
		} else if (dstkind == OP_MEM) {
#if SYMBOLIC
			if (ismemsym(dstval, bw))
				delmemsyms(dstval, bw);
#endif

			depcheck(dstval, DEP_W);
			if (bw)
				memory[dstval] = (res & 0xff);
			else
				memwriteword(dstval, res);
		} else if (dstkind == OP_CONST) {
			ASSERT(instr == 0x3, "instr: %04x", instr);
		} else
			ASSERT(dstkind == OP_FLAGSONLY, "x: %u", dstkind);
#if SYMBOLIC
	}
#endif
}

void
handle_double(uint16_t instr)
{
	enum operand_kind srckind, dstkind;
	uint16_t dsrc = bits(instr, 11, 8) >> 8,
		 Ad = bits(instr, 7, 7),
		 bw = bits(instr, 6, 6),
		 As = bits(instr, 5, 4),
		 ddst = bits(instr, 3, 0);
	uint16_t srcval /*absolute addr or register number or constant*/,
		 dstval /*absolute addr or register number*/;
	unsigned res = (unsigned)-1,
		 dstnum = 0, srcnum = 0 /*as a number*/;
	uint16_t setflags = 0,
		 clrflags = 0;
#if SYMBOLIC
	struct sexp *srcsym = NULL, *ressym = NULL, *dstsym = NULL,
		      *flagsym = NULL;
#endif

	inc_reg(PC, 0);

	// Bogus initialization to quiet GCC
	srckind = OP_FLAGSONLY;
	srcval = 0xffff;

	load_src(instr, dsrc, As, bw, &srcval, &srckind);
	load_dst(instr, ddst, Ad, &dstval, &dstkind);

	if (off)
		return;

	// Load addressed src values
	switch (srckind) {
	case OP_REG:
#if SYMBOLIC
		if (isregsym(srcval))
			srcsym = regsym(srcval);
		else
#endif
			srcnum = registers[srcval];
		break;
	case OP_MEM:
#if SYMBOLIC
		if (ismemsym(srcval, bw))
			srcsym = memsym(srcval, bw);
		else {
#endif
			if (bw)
				srcnum = membyte(srcval);
			else
				srcnum = memword(srcval);
#if SYMBOLIC
		}
#endif
		break;
	case OP_CONST:
		srcnum = srcval;
		break;
	default:
		ASSERT(false, "illins");
		break;
	}

	// Load addressed dst values
	switch (dstkind) {
	case OP_REG:
#if SYMBOLIC
		if (isregsym(dstval))
			dstsym = regsym(dstval);
		else
#endif
			dstnum = registers[dstval];
		break;
	case OP_MEM:
#if SYMBOLIC
		if (ismemsym(dstval, bw))
			dstsym = memsym(dstval, bw);
		else {
#endif
			if (bw)
				dstnum = membyte(dstval);
			else
				dstnum = memword(dstval);
#if SYMBOLIC
		}
#endif
		break;
	case OP_CONST:
		ASSERT(instr == 0x4303 || instr == 0x03, "nop");
		return;
	default:
		ASSERT(false, "illins");
		break;
	}

#if SYMBOLIC
	// If either input is symbolic, both are. Put the other value in a
	// temporary symbol.
	if (srcsym && dstsym == NULL) {
		dstsym = sexp_imm_alloc(dstnum);
	} else if (dstsym && srcsym == NULL) {
		srcsym = sexp_imm_alloc(srcnum);
	}
#endif

	switch (bits(instr, 15, 12)) {
	case 0x4000:
		// MOV (no flags)
#if SYMBOLIC
		if (srcsym)
			ressym = srcsym;
		else
#endif
			res = srcnum;
		break;
	case 0x5000:
		// ADD (flags)
#if SYMBOLIC
		if (srcsym) {
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = peephole(mksexp(S_PLUS, 2, srcsym, dstsym));
			flagsym = mksexp(S_AND, 2, mksexp(S_SR, 1, ressym), &SEXP_00FF);
		} else {
#endif
			if (bw) {
				dstnum &= 0xff;
				srcnum &= 0xff;
			}
			res = dstnum + srcnum;
			addflags(res, bw, &setflags, &clrflags);
			if (bw)
				res &= 0x00ff;
			else
				res &= 0xffff;
#if SYMBOLIC
		}
#endif
		break;
	case 0x6000:
		// ADDC (flags)
#if SYMBOLIC
		if (srcsym) {
			printf("XXX symbolic ADDC ->SR\n");
			abort_nodump();
		} else {
#endif
			if (bw) {
				dstnum &= 0xff;
				srcnum &= 0xff;
			}
#if SYMBOLIC
			ASSERT(!isregsym(SR), "TODO");
#endif
			res = dstnum + srcnum + ((registers[SR] & SR_C) ? 1 : 0);
			addflags(res, bw, &setflags, &clrflags);
			if (bw)
				res &= 0x00ff;
			else
				res &= 0xffff;
#if SYMBOLIC
		}
#endif
		break;
	case 0x9000:
		// CMP (flags)
		dstkind = OP_FLAGSONLY;
		// FALLTHROUGH
	case 0x8000:
		// SUB (flags)
#if SYMBOLIC
		if (srcsym) {
			srcsym = mksexp(S_XOR, 2, srcsym, &SEXP_NEG_1);
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = mksexp(S_PLUS, 3, srcsym, dstsym,
			    sexp_imm_alloc(1));
			flagsym = mksexp(S_AND, 2,
			    mksexp(S_SR, 1, peephole(ressym)),
			    &SEXP_00FF);
		} else {
#endif
			srcnum = ~srcnum & 0xffff;
			if (bw) {
				dstnum &= 0xff;
				srcnum &= 0xff;
			}
			res = dstnum + srcnum + 1;
			addflags(res, bw, &setflags, &clrflags);
			if (bw)
				res &= 0x00ff;
			else
				res &= 0xffff;
#if SYMBOLIC
		}
#endif
		break;
	case 0xa000:
		// DADD (flags)
#if SYMBOLIC
		if (srcsym) {
			printf("XXX symbolic DADD ->SR\n");
			abort_nodump();
		} else
#endif
		{
			unsigned carry = 0;
			bool setn = false;

			res = 0;
			for (unsigned i = 0; i < ((bw)? 8 : 16); i += 4) {
				unsigned a = bits(srcnum, i+3, i) >> i,
					 b = bits(dstnum, i+3, i) >> i,
					 partial;
				partial = a + b + carry;
				setn = !!(partial & 0x8);
				if (partial >= 10) {
					partial -= 10;
					carry = 1;
				} else
					carry = 0;

				res |= ((partial & 0xf) << i);
			}

			if (setn)
				setflags |= SR_N;
			if (carry)
				setflags |= SR_C;
			else
				clrflags |= SR_C;
		}
		break;
	case 0xc000:
		// BIC
#if SYMBOLIC
		if (srcsym) {
			printf("XXX symbolic BIC\n");
			abort_nodump();
		} else
#endif
			res = dstnum & ~srcnum;
		break;
	case 0xd000:
		// BIS (no flags)
#if SYMBOLIC
		if (srcsym) {
			printf("XXX symbolic BIS\n");
			abort_nodump();
		} else
#endif
			res = dstnum | srcnum;
		break;
	case 0xe000:
		// XOR (flags)
#if SYMBOLIC
		if (srcsym) {
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = mksexp(S_XOR, 2, srcsym, dstsym);
			flagsym = mksexp(S_SR_AND, 1, peephole(ressym));
		} else {
#endif
			res = dstnum ^ srcnum;
			if (bw)
				res &= 0x00ff;
			andflags(res, &setflags, &clrflags);
#if SYMBOLIC
		}
#endif
		break;
	case 0xb000:
		// BIT
		dstkind = OP_FLAGSONLY;
		// FALLTHROUGH
	case 0xf000:
		// AND (flags)
#if SYMBOLIC
		if (srcsym) {
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = mksexp(S_AND, 2, srcsym, dstsym);
			flagsym = mksexp(S_SR_AND, 1, peephole(ressym));
		} else {
#endif
			res = dstnum & srcnum;
			if (bw)
				res &= 0x00ff;
			andflags(res, &setflags, &clrflags);
#if SYMBOLIC
		}
#endif
		break;
	default:
		unhandled(instr);
		break;
	}

#if SYMBOLIC
	// concretify
	if (ressym && ressym->s_kind == S_IMMEDIATE) {
		res = ressym->s_nargs & 0xffff;
		sexp_flags(flagsym, &setflags, &clrflags);
		ressym = NULL;
	}

	if (ressym) {
		if (flagsym)
			register_symbols[SR] = peephole(flagsym);

		if (bw)
			ressym = bytemask(ressym);

		if (dstkind == OP_REG)
			register_symbols[dstval] = peephole(ressym);
		else if (dstkind == OP_MEM)
			memwritesym(dstval, bw, peephole(ressym));
		else {
			ASSERT(dstkind == OP_FLAGSONLY, "x");
			ressym = NULL;
		}
	} else {
#endif
		if (setflags || clrflags) {
			ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
#if SYMBOLIC
			if (isregsym(SR)) {
				struct sexp *s = sexp_alloc(S_OR), *t;
				s->s_nargs = 2;
				s->s_arg[0] = regsym(SR);
				s->s_arg[1] = sexp_imm_alloc(setflags);
				t = sexp_alloc(S_AND);
				t->s_nargs = 2;
				t->s_arg[0] = s;
				t->s_arg[1] = sexp_imm_alloc(~clrflags & 0x1ff);
				register_symbols[SR] = peephole(t);
			} else {
#endif
				registers[SR] |= setflags;
				registers[SR] &= ~clrflags;
				registers[SR] &= 0x1ff;
#if SYMBOLIC
			}
#endif
		}

		if (dstkind == OP_REG) {
			ASSERT(res != (unsigned)-1, "res never set");

			if (bw)
				res &= 0x00ff;

#if SYMBOLIC
			if (isregsym(dstval))
				register_symbols[dstval] = NULL;
#endif

			registers[dstval] = res & 0xffff;
		} else if (dstkind == OP_MEM) {
#if SYMBOLIC
			if (ismemsym(dstval, bw))
				delmemsyms(dstval, bw);
#endif
			depcheck(dstval, DEP_W);
			if (bw)
				memory[dstval] = (res & 0xff);
			else
				memwriteword(dstval, res);
		} else
			ASSERT(dstkind == OP_FLAGSONLY, "x");
#if SYMBOLIC
	}
#endif
}

// R0 only supports AS_IDX, AS_INDINC (inc 2), AD_IDX.
// R2 only supports AS_R2_*, AD_R2_ABS (and direct for both).
// R3 only supports As (no Ad).

void
load_src(uint16_t instr, uint16_t instr_decode_src, uint16_t As, uint16_t bw,
    uint16_t *srcval, enum operand_kind *srckind)
{
	uint16_t extensionword;

	switch (instr_decode_src) {
	case SR:
		switch (As) {
		case AS_REG:
			*srckind = OP_REG;
			*srcval = instr_decode_src;
			break;
		case AS_R2_ABS:
#if SYMBOLIC
			ASSERT(!ismemsym(registers[PC], 0), "symbolic ext. word");
#endif
			extensionword = memword(registers[PC]);
			inc_reg(PC, 0);
			instr_size += 2;

			*srckind = OP_MEM;
			*srcval = extensionword;
			break;
		case AS_R2_4:
			*srckind = OP_CONST;
			*srcval = 4;
			break;
		case AS_R2_8:
			*srckind = OP_CONST;
			*srcval = 8;
			break;
		default:
			illins(instr);
			break;
		}
		break;
	case CG:
		switch (As) {
		case AS_R3_0:
			*srckind = OP_CONST;
			*srcval = 0;
			break;
		case AS_R3_1:
			*srckind = OP_CONST;
			*srcval = 1;
			break;
		case AS_R3_2:
			*srckind = OP_CONST;
			*srcval = 2;
			break;
		case AS_R3_NEG:
			*srckind = OP_CONST;
			*srcval = 0xffff;
			break;
		default:
			illins(instr);
			break;
		}
		break;
	default:
		switch (As) {
		case AS_REG:
			*srckind = OP_REG;
			*srcval = instr_decode_src;
			break;
		case AS_IDX:
#if SYMBOLIC
			ASSERT(!ismemsym(registers[PC], 0), "symbolic ext. word");
#endif
			extensionword = memword(registers[PC]);
			inc_reg(PC, 0);
			instr_size += 2;
			*srckind = OP_MEM;
#if SYMBOLIC
			ASSERT(!isregsym(instr_decode_src), "symbolic load addr"
			    " (r%d)", instr_decode_src);
#endif
			*srcval = (registers[instr_decode_src] + extensionword)
			    & 0xffff;
			break;
		case AS_REGIND:
			*srckind = OP_MEM;
#if SYMBOLIC
			ASSERT(!isregsym(instr_decode_src), "symbolic load addr"
			    " (r%d)", instr_decode_src);
#endif
			*srcval = registers[instr_decode_src];
			break;
		case AS_INDINC:
			*srckind = OP_MEM;

#if SYMBOLIC
			if (isregsym(instr_decode_src)) {
				printf("symbolic load reg(%u)\n", instr_decode_src);
				printsym(regsym(instr_decode_src));
				printf("\n");
			}

			ASSERT(!isregsym(instr_decode_src), "symbolic load addr"
			    " (r%d)", instr_decode_src);
#endif
			*srcval = registers[instr_decode_src];
			inc_reg(instr_decode_src, bw);
			if (instr_decode_src == PC)
				instr_size += 2;
			break;
		default:
			illins(instr);
			break;
		}
		break;
	}
}

// R0 only supports AS_IDX, AS_INDINC (inc 2), AD_REG, AD_IDX.
// R2 only supports AS_R2_*, AD_R2_ABS.
// R3 only supports As (no Ad).

void
load_dst(uint16_t instr, uint16_t instr_decode_dst, uint16_t Ad,
    uint16_t *dstval, enum operand_kind *dstkind)
{
	uint16_t extensionword;

	if (instr_decode_dst == CG) {
#ifdef BF
		if (instr != 0x4303 && instr != 0x0003)
			illins(instr);
#else
		ASSERT(instr == 0x4303, "nop");
#endif
		*dstkind = OP_CONST;
		*dstval = 0;
		return;
	}

	if (Ad == AD_REG) {
		*dstkind = OP_REG;
		*dstval = instr_decode_dst;
	} else {
		uint16_t regval = 0;

		ASSERT(Ad == AD_IDX, "Ad");

#if SYMBOLIC
		ASSERT(!ismemsym(registers[PC], 0), "symbolic ext. word");
#endif
		extensionword = memword(registers[PC]);
		inc_reg(PC, 0);
		instr_size += 2;

		if (instr_decode_dst != SR) {
#if SYMBOLIC
			ASSERT(!isregsym(instr_decode_dst), "symbolic load addr"
			    " (r%d)", instr_decode_dst);
#endif
			regval = registers[instr_decode_dst];
		}

		*dstkind = OP_MEM;
		*dstval = (regval + extensionword) & 0xffff;
	}
}

void
_unhandled(const char *f, unsigned l, uint16_t instr)
{

#ifdef BF
	off = true;
#else
	printf("%s:%u: Instruction: %#04x @PC=%#04x is not implemented\n",
	    f, l, (unsigned)instr, (unsigned)pc_start);
	printf("Raw at PC: ");
	for (unsigned i = 0; i < 6; i++)
		printf("%02x", memory[pc_start+i]);
	printf("\n");
	abort_nodump();
#endif
}

void
_illins(const char *f, unsigned l, uint16_t instr)
{

#ifdef BF
	off = true;
#else
	printf("%s:%u: ILLEGAL Instruction: %#04x @PC=%#04x\n",
	    f, l, (unsigned)instr, (unsigned)pc_start);
	printf("Raw at PC: ");
	for (unsigned i = 0; i < 6; i++)
		printf("%02x", memory[pc_start+i]);
	printf("\n");
	abort_nodump();
#endif
}

uint16_t
membyte(uint16_t addr)
{

#if SYMBOLIC
	ASSERT(!ismemsym(addr, 1), "wrong api for symbolic load");
#endif
	return memory[addr];
}

#ifndef REALLYFAST
uint16_t
memword(uint16_t addr)
{

	ASSERT((addr & 0x1) == 0, "word load unaligned: %#04x",
	    (unsigned)addr);
#if SYMBOLIC
	ASSERT(!ismemsym(addr, 0), "wrong api for symbolic load");
#endif
	return memory[addr] | ((uint16_t)memory[addr+1] << 8);
}
#endif

#ifndef REALLYFAST
uint16_t
bits(uint16_t v, unsigned max, unsigned min)
{
	uint16_t mask;

	ASSERT(max < 16 && max >= min, "bit-select");
	ASSERT(min < 16, "bit-select");

	mask = ((unsigned)1 << (max+1)) - 1;
	if (min > 0)
		mask &= ~( (1<<min) - 1 );

	return v & mask;
}
#endif

void
abort_nodump(void)
{

	print_regs();
	print_ips();

#ifndef EMU_CHECK
	gdbstub_stopped();
#endif
	exit(1);
}

static void
printmemword(const char *pre, uint16_t addr)
{

	printf("%s", pre);
#if SYMBOLIC
	if (ismemsym(addr+1, 1))
		printf("??");
	else
#endif
		printf("%02x", membyte(addr+1));
#if SYMBOLIC
	if (ismemsym(addr, 1))
		printf("??");
	else
#endif
		printf("%02x", membyte(addr));
}

static void
printreg(unsigned reg)
{

#if SYMBOLIC
	if (isregsym(reg)) {
		printf("????  ");
		return;
	}
#endif

	printf("%04x  ", registers[reg]);
}

void
print_regs(void)
{

	printf("pc  ");
	printreg(PC);
	printf("sp  ");
	printreg(SP);
	printf("sr  ");
	printreg(SR);
	printf("cg  ");
	printreg(CG);
	printf("\n");

	for (unsigned i = 4; i < 16; i += 4) {
		for (unsigned j = i; j < i + 4; j++) {
			printf("r%02u ", j);
			printreg(j);
		}
		printf("\n");
	}

	printf("instr:");
	for (unsigned i = 0; i < 4; i++)
		printmemword("  ", (pc_start & 0xfffe) + 2*i);
	printf("\nstack:");
	for (unsigned i = 0; i < 4; i++)
		printmemword("  ", (registers[SP] & 0xfffe) + 2*i);
	printf("\n      ");
	for (unsigned i = 4; i < 8; i++)
		printmemword("  ", (registers[SP] & 0xfffe) + 2*i);
	printf("\n");

#if SYMBOLIC
	for (unsigned i = 0; i < 16; i++) {
		if (!isregsym(i))
			continue;

		printf("r%d is symbolic:\n", i);
		printsym(regsym(i));
		printf("/r%d\n", i);
	}
	printf("\n");
#endif
}

uint16_t
sr_flags(void)
{

#if SYMBOLIC
	ASSERT(!isregsym(SR), "TODO");
#endif
	return registers[SR] & (SR_V | SR_CPUOFF | SR_N | SR_Z | SR_C);
}

#ifndef REALLYFAST
void
memwriteword(uint16_t addr, uint16_t word)
{

	ASSERT((addr & 0x1) == 0, "word store unaligned: %#04x",
	    (uns)addr);
	memory[addr] = word & 0xff;
	memory[addr+1] = (word >> 8) & 0xff;
}
#endif

#ifndef REALLYFAST
void
addflags(unsigned res, uint16_t bw, uint16_t *set, uint16_t *clr)
{
	unsigned sz = 16;

	if (bw)
		sz = 8;

	if (bw == 0 && (res & 0x8000))
		*set |= SR_N;
	else
		*clr |= SR_N;

	// #uctf never sets V. Only clear on arithmetic, though.
	*clr |= SR_V;
	*clr |= 0xfe00;
#if 0
	if ((res & 0x8000) ^ (orig & 0x8000))
		*set |= SR_V;
#endif

	if ((res & ((1 << sz) - 1)) == 0)
		*set |= SR_Z;
	else
		*clr |= SR_Z;

	if (res & (1 << sz))
		*set |= SR_C;
	else
		*clr |= SR_C;
}
#endif

// set flags based on result; used in AND, SXT, ...
void
andflags(uint16_t res, uint16_t *set, uint16_t *clr)
{

	*clr |= SR_V;
	*clr |= 0xfe00;

	if (res & 0x8000)
		*set |= SR_N;
	else
		*clr |= SR_N;
	if (res == 0) {
		*set |= SR_Z;
		*clr |= SR_C;
	} else {
		*clr |= SR_Z;
		*set |= SR_C;
	}
}

uint64_t
now(void)
{
	struct timespec ts;
	int rc;

	rc = clock_gettime(CLOCK_REALTIME, &ts);
	ASSERT(rc == 0, "clock_gettime: %d:%s", errno, strerror(errno));

	return ((uint64_t)sec * ts.tv_sec + (ts.tv_nsec / 1000));
}

void
callgate(unsigned op)
{
	uint16_t argaddr = registers[SP] + 8,
		 getsaddr;
	unsigned bufsz;

	switch (op) {
	case 0x0:
#ifndef QUIET
		if (!replay_mode)
			putchar((char)membyte(argaddr));
#endif
		break;
	case 0x2:
		getsaddr = memword(argaddr);
		bufsz = (uns)memword(argaddr+2);
#if SYMBOLIC
		ASSERT(!replay_mode, "x");
		ASSERT((uns)getsaddr + (uns)bufsz < 0x10000, "overflow");
		bufsz = min((uns)syminplen, bufsz-1);
		memset(&memory[getsaddr], 0, bufsz+1);
		for (unsigned i = 0; i < bufsz; i++) {
			struct sexp *s;

			s = sexp_alloc(S_INP);
			s->s_nargs = i;
			g_hash_table_insert(memory_symbols, ptr(getsaddr+i), s);
		}
		printf(" < tracking symbolic input (%u bytes) >\n",
		    (uns)syminplen);
#else
		getsn(getsaddr, bufsz);
#endif
		break;
	case 0x10:
		// Turn on DEP
		if (dep_enabled)
			break;
		for (unsigned i = 0; i < sizeof(pageprot); i++) {
			if ((pageprot[i] & DEP_W) && (pageprot[i] & DEP_X)) {
				printf("Enable DEP invalid: page %u +WX!\n",
				    i);
				abort_nodump();
			}
		}
		dep_enabled = true;
		break;
	case 0x11:
		// Set page protection
		{
		uint16_t page, wr;
		page = memword(argaddr);
		wr = memword(argaddr+2);

		ASSERT(page < 0x100, "page");
		ASSERT(wr == 0 || wr == 1, "w/x");

		pageprot[page] &= ~( wr? DEP_X : DEP_W );
		}
		break;
	case 0x20:
		// RNG
		registers[15] = 0;
		break;
	case 0x7d:
		// writes a non-zero byte to supplied pointer if password is
		// correct (arg[0]). password is never correct.
		memory[memword(argaddr+2)] = 0;
		break;
	case 0x7e:
		// triggers unlock if password is correct; nop
		break;
	case 0x7f:
		// unlock.
		win();
		break;
	default:
		unhandled(0x4130);
		break;
	}
}

void
win(void)
{

	printf("The lock opens; you win!\n\n");
	print_regs();
	print_ips();
	off = true;
	unlocked = true;
}

#ifndef EMU_CHECK
static void
ins_inprec(char *dat, size_t sz)
{
	struct inprec *new_inp = malloc(sizeof *new_inp + sz + 1);

	ASSERT(new_inp, "oom");

	new_inp->ir_insn = insns;
	new_inp->ir_len = sz + 1;
	memcpy(new_inp->ir_inp, dat, sz);
	new_inp->ir_inp[sz] = 0;

	g_hash_table_insert(input_record, ptr(insns), new_inp);
}

void
getsn(uint16_t addr, uint16_t bufsz)
{
	struct inprec *prev_inp;
	char *buf;

	ASSERT((size_t)addr + bufsz < 0xffff, "overflow");
	//memset(&memory[addr], 0, bufsz);

	if (bufsz <= 1)
		return;

	prev_inp = g_hash_table_lookup(input_record, ptr(insns));
	if (replay_mode)
		ASSERT(prev_inp, "input at insn:%ju not found!\n",
		    (uintmax_t)insns);

	if (prev_inp) {
		memcpy(&memory[addr], prev_inp->ir_inp, prev_inp->ir_len);
		return;
	}

	printf("Gets (':'-prefix for hex)> ");
	fflush(stdout);

	buf = malloc(2 * bufsz + 2);
	ASSERT(buf, "oom");
	buf[0] = 0;

	if (fgets(buf, 2 * bufsz + 2, stdin) == NULL)
		goto out;

	if (buf[0] != ':') {
		size_t len;

		len = strlen(buf);
		while (len > 0 &&
		    (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
			buf[len - 1] = '\0';
			len--;
		}

		strncpy((char*)&memory[addr], buf, bufsz);
		memory[addr + strlen(buf)] = 0;
		ins_inprec(buf, bufsz);
	} else {
		unsigned i;
		for (i = 0; i < bufsz - 1u; i++) {
			unsigned byte;

			if (buf[2*i+1] == 0 || buf[2*i+2] == 0) {
				memory[addr+i] = 0;
				break;
			}

			sscanf(&buf[2*i+1], "%02x", &byte);
			//printf("%02x", byte);
			memory[addr + i] = byte;
		}
		ins_inprec((void*)&memory[addr], i);
	}
out:
	free(buf);
}
#endif

#if SYMBOLIC
bool
isregsym(uint16_t reg)
{
	struct sexp *r;

	r = register_symbols[reg];
	return (r != NULL);
}

struct sexp *
regsym(uint16_t reg)
{
	struct sexp *r;

	r = register_symbols[reg];
	return r;
}

bool
ismemsym(uint16_t addr, uint16_t bw)
{
	struct sexp *b1, *b2 = NULL;

	b1 = g_hash_table_lookup(memory_symbols, ptr(addr));
	if (bw == 0)
		b2 = g_hash_table_lookup(memory_symbols, ptr(addr + 1));

	return (b1 || b2);
}

struct sexp *
memsym(uint16_t addr, uint16_t bw)
{
	struct sexp *b1, *b2 = NULL;

	b1 = g_hash_table_lookup(memory_symbols, ptr(addr));
	if (bw)
		return b1;

	ASSERT((addr & 1) == 0, "unaligned word read");
	b2 = g_hash_table_lookup(memory_symbols, ptr(addr + 1));

	ASSERT(b1 || b2, "memory is concrete");

	if (b1 == NULL)
		b1 = sexp_imm_alloc(membyte(addr));
	if (b2)
		b2 = peephole(mksexp(S_LSHIFT, 2, b2, &SEXP_8));
	else
		b2 = sexp_imm_alloc(membyte(addr+1) << 8);

	return mksexp(S_OR, 2, b2, b1);
}

static void
_printsym(struct sexp *sym, unsigned indent)
{

	for (unsigned i = 0; i < indent; i++)
		printf("  ");

	if (sym->s_kind == S_IMMEDIATE) {
		printf("0x%04x\n", sym->s_nargs);
		return;
	}

	if (sym->s_kind == S_INP) {
		printf("Input[%d]\n", sym->s_nargs);
		return;
	}

	if (indent >= 20) {
		printf("...\n");
		return;
	}

	printf("(");
	switch (sym->s_kind) {
	case S_OR:
		printf("|");
		break;
	case S_XOR:
		printf("^");
		break;
	case S_AND:
		printf("&");
		break;
	case S_PLUS:
		printf("+");
		break;
	case S_SR:
		printf("sr");
		break;
	case S_EQ:
		printf("==");
		ASSERT(sym->s_nargs == 2, "x");
		break;
	case S_SR_AND:
		printf("sr-and");
		break;
	case S_SR_RRC:
		printf("sr-rrc");
		break;
	case S_SR_RRA:
		printf("sr-rra");
		break;
	case S_RSHIFT:
		printf(">>");
		ASSERT(sym->s_nargs == 2, "x");
		break;
	case S_LSHIFT:
		printf("<<");
		ASSERT(sym->s_nargs == 2, "x");
		break;
	case S_RRA:
		printf("rra");
		ASSERT(sym->s_nargs == 2, "x");
		break;
	case S_SXT:
		printf("sxt");
		ASSERT(sym->s_nargs == 1, "x");
		break;
	default:
		ASSERT(false, "what kind is it? %d", sym->s_kind);
		break;
	}

	//printf(":%d\n", sym->s_nargs);
	printf("\n");
	for (unsigned i = 0; i < sym->s_nargs; i++) {
		//printf(" ");
		_printsym(sym->s_arg[i], indent + 1);
	}

	for (unsigned i = 0; i < indent; i++)
		printf("  ");
	printf(")\n");
}

void
printsym(struct sexp *sym)
{

	if (sym == NULL)
		return;

	_printsym(sym, 0);
	printf("\n");
}

void
delmemsyms(uint16_t addr, uint16_t bw)
{

	g_hash_table_remove(memory_symbols, ptr(addr));
	if (bw)
		return;
	g_hash_table_remove(memory_symbols, ptr(addr+1));
}

void
memwritesym(uint16_t addr, uint16_t bw, struct sexp *s)
{
	struct sexp *low, *high;

	if (bw) {
		s = peephole(bytemask(s));
		g_hash_table_insert(memory_symbols, ptr(addr), s);
		return;
	}

	low = peephole(mksexp(S_AND, 2, s, sexp_imm_alloc(0xff)));
	high = peephole(mksexp(S_RSHIFT, 2, s, &SEXP_8));

	g_hash_table_insert(memory_symbols, ptr(addr), low);
	g_hash_table_insert(memory_symbols, ptr(addr+1), high);
}

static struct sexp *
peep_constreduce(struct sexp *s, bool *changed)
{

	// (<< 0 ...) -> 0
	if (s->s_nargs > 0 && s->s_kind == S_LSHIFT &&
	    s->s_arg[0]->s_kind == S_IMMEDIATE && s->s_arg[0]->s_nargs == 0) {
		s = s->s_arg[0];
		*changed = true;
		return s;
	}

	if (s->s_nargs < 2)
		return s;

	// (x imm imm ...) -> (x imm)
	for (unsigned n = 3; n > 0; n--) {
		if (s->s_nargs > n && s->s_arg[n-1]->s_kind == S_IMMEDIATE &&
		    s->s_arg[n]->s_kind == S_IMMEDIATE) {
			unsigned nargs = s->s_nargs;
			struct sexp *n1 = NULL;
			enum sexp_kind sk = s->s_kind;

			switch (sk) {
			case S_PLUS:
				n1 = sexp_imm_alloc(
				    s->s_arg[n-1]->s_nargs +
				    s->s_arg[n]->s_nargs);
				*changed = true;
				break;
			case S_OR:
				n1 = sexp_imm_alloc(
				    s->s_arg[n-1]->s_nargs |
				    s->s_arg[n]->s_nargs);
				*changed = true;
				break;
			case S_AND:
				n1 = sexp_imm_alloc(
				    s->s_arg[n-1]->s_nargs &
				    s->s_arg[n]->s_nargs);
				*changed = true;
				break;
			case S_XOR:
				n1 = sexp_imm_alloc(
				    s->s_arg[n-1]->s_nargs ^
				    s->s_arg[n]->s_nargs);
				*changed = true;
				break;
			case S_RSHIFT:
				ASSERT(n == 1, ">>");
				s = sexp_imm_alloc(s->s_arg[n-1]->s_nargs >>
				    s->s_arg[n]->s_nargs);
				*changed = true;
				break;
			case S_LSHIFT:
				ASSERT(n == 1, "<<");
				s = sexp_imm_alloc(s->s_arg[n-1]->s_nargs <<
				    s->s_arg[n]->s_nargs);
				*changed = true;
				break;
			case S_RRA:
				{
				int16_t imm;

				// (>>/ imm 1) -> (/ imm 2)
				ASSERT(n == 1, "rra");
				ASSERT(s->s_arg[n]->s_nargs == 1, "/ 2");

				imm = (int16_t)s->s_arg[n-1]->s_nargs;

				if (imm == -1)
					s = &SEXP_NEG_1;
				else
					s = sexp_imm_alloc(imm / 2);
				*changed = true;
				}
				break;
			case S_EQ:
				ASSERT(n == 1, "eq");
				if (s->s_arg[n]->s_nargs ==
				    s->s_arg[n-1]->s_nargs)
					s = &SEXP_1;
				else
					s = &SEXP_0;
				*changed = true;
				break;
			default:
				break;
			}

			if (*changed && sk != S_RSHIFT && sk != S_LSHIFT && sk
			    != S_RRA && sk != S_EQ) {
				struct sexp *t;

				ASSERT(n1, "x");
				t = mksexp(sk, 0);
				t->s_nargs = nargs - 1;
				for (unsigned i = 0; i < nargs - 2; i++)
					t->s_arg[i] = s->s_arg[i];
				t->s_arg[nargs - 2] = n1;
				s = t;
			}
		}
	}

	// TODO (x imm) -> imm?

	if (*changed)
		return s;

	if (s->s_nargs != 2)
		return s;

	if (s->s_arg[1]->s_kind != S_IMMEDIATE)
		return s;

	// (x non-imm imm)
	switch (s->s_kind) {
	case S_AND:
		if (s->s_arg[1]->s_nargs == 0) {
			// (& x 0) -> 0
			s = s->s_arg[1];
			*changed = true;
		} else if (s->s_arg[1]->s_nargs == 0xffff) {
			// (& x ffff) -> x
			s = s->s_arg[0];
			*changed = true;
		} else if (s->s_arg[0]->s_kind == S_INP &&
		    (s->s_arg[1]->s_nargs & 0xff) == 0xff) {
			// (& Inp 0xYYff) -> Inp
			s = s->s_arg[0];
			*changed = true;
		}
		break;
	case S_XOR:
		if (s->s_arg[1]->s_nargs == 0) {
			// (^ x 0) -> x
			s = s->s_arg[0];
			*changed = true;
		}
		break;
	case S_PLUS:
		if (s->s_arg[1]->s_nargs == 0) {
			// (+ x 0) -> x
			s = s->s_arg[0];
			*changed = true;
		}
		break;
	case S_OR:
		if (s->s_arg[1]->s_nargs == 0) {
			// (| x 0) -> x
			s = s->s_arg[0];
			*changed = true;
		} else if (s->s_arg[1]->s_nargs == 0xffff) {
			// (| x ffff) -> ffff
			s = s->s_arg[1];
			*changed = true;
		}
		break;
	case S_RSHIFT:
		if (s->s_arg[1]->s_nargs >= 16) {
			// (>> X 16) -> 0
			s = &SEXP_0;
			*changed = true;
		} else if (s->s_arg[1]->s_nargs >= 8 &&
		    s->s_arg[0]->s_kind == S_INP) {
			// (>> Inp 8) -> 0
			s = &SEXP_0;
			*changed = true;
		}
		break;
	case S_LSHIFT:
		if (s->s_arg[1]->s_nargs >= 16) {
			// (<< X 16) -> 0
			s = &SEXP_0;
			*changed = true;
		}
		break;
	default:
		break;
	}

	return s;
}

static struct sexp *
peep_expfirst(struct sexp *s, bool *changed)
{

	if (s->s_nargs < 2)
		return s;

	switch (s->s_kind) {
	case S_PLUS:
	case S_OR:
	case S_AND:
	case S_XOR:
	case S_EQ:
		if (s->s_arg[0]->s_kind == S_IMMEDIATE &&
		    s->s_arg[1]->s_kind != S_IMMEDIATE) {
			struct sexp **t;
			unsigned nargs;

			nargs = s->s_nargs;
			t = &s->s_arg[0];

			s = mksexp(s->s_kind, 2,
			    t[1], t[0]);

			for (unsigned i = 2; i < nargs; i++)
				s->s_arg[i] = t[i];

			s->s_nargs = nargs;
			*changed = true;
		}
		break;
	default:
		break;
	}

	return s;
}

static struct sexp *
sexpflatten(struct sexp *s, unsigned argn)
{
	struct sexp *t, *res;
	unsigned i, j;

	t = s->s_arg[argn];

	res = mksexp(s->s_kind, 0);
	for (i = 0; i < argn; i++)
		res->s_arg[i] = s->s_arg[i];
	for (j = 0; j < t->s_nargs; j++)
		res->s_arg[i++] = t->s_arg[j];
	for (j = argn + 1; j < s->s_nargs; j++)
		res->s_arg[i++] = s->s_arg[j];
	res->s_nargs = s->s_nargs + t->s_nargs - 1;

	return res;
}

static struct sexp *
peep_flatten(struct sexp *s, bool *changed)
{

	if (s->s_nargs == 0) {
		printf("args = 0 >>\n");
		printsym(s);
		ASSERT(false, "args");
	}

	switch (s->s_kind) {
	case S_PLUS:
	case S_AND:
	case S_XOR:
	case S_OR:
		break;
	default:
		return s;
	}

	// (+ x) -> x, etc.
	if (s->s_nargs == 1) {
		*changed = true;
		return s->s_arg[0];
	}

	// (^ (^ ...) ...) -> (^ ... ...)
	for (unsigned i = 0; i < s->s_nargs; i++) {
		if (s->s_arg[i]->s_kind == s->s_kind &&
		    s->s_arg[i]->s_nargs + s->s_nargs - 1 <= SEXP_MAXARGS) {
			*changed = true;
			return sexpflatten(s, i);
		}
	}

	return s;
}

//  s      X  i1   i2
// (<< (<< X imm) imm)
static uint16_t dlshift_imm1, dlshift_imm2;
static struct sexp *dlshift_sub;
STATIC_PATTERN(dlshift_pattern,
    mksexp(S_LSHIFT, 2,
	mksexp(S_LSHIFT, 2,
	    subsexp(&dlshift_sub),
	    subimm(&dlshift_imm1)),
	subimm(&dlshift_imm2)));

static struct sexp *
peep_dlshiftflatten(struct sexp *s, bool *changed)
{

	ASSERT(s->s_nargs == 2, "contract");
	ASSERT(s->s_kind == S_LSHIFT, "contract");

	dlshift_imm1 = dlshift_imm2 = 0;
	dlshift_sub = NULL;

	if (!sexpmatch(dlshift_pattern, s))
		return s;

	*changed = true;
	return mksexp(S_LSHIFT, 2,
	    dlshift_sub,
	    sexp_imm_alloc(dlshift_imm1 + dlshift_imm2));
}

// (>> (>> X imm) imm)
static uint16_t drshift_imm1, drshift_imm2;
static struct sexp *drshift_sub;
STATIC_PATTERN(drshift_pattern,
    mksexp(S_RSHIFT, 2,
	mksexp(S_RSHIFT, 2,
	    subsexp(&drshift_sub),
	    subimm(&drshift_imm1)),
	subimm(&drshift_imm2)));

static struct sexp *
peep_drshiftflatten(struct sexp *s, bool *changed)
{

	ASSERT(s->s_nargs == 2, "contract");
	ASSERT(s->s_kind == S_RSHIFT, "contract");

	drshift_imm1 = drshift_imm2 = 0;
	drshift_sub = NULL;

	if (!sexpmatch(drshift_pattern, s))
		return s;

	*changed = true;
	return mksexp(S_RSHIFT, 2,
	    drshift_sub,
	    sexp_imm_alloc(drshift_imm1 + drshift_imm2));
}

static struct sexp *
peep_xorident(struct sexp *s, bool *changed)
{

	if (s->s_nargs < 2)
		return s;

	// (^ a b a c) -> (^ b c)
	for (unsigned i = 0; i < s->s_nargs - 1; i++) {
		for (unsigned j = i + 1; j < s->s_nargs; j++) {
			if (sexp_eq(s->s_arg[i], s->s_arg[j])) {
				struct sexp *res;
				unsigned k, l;

				*changed = true;
				ASSERT(i < j, "by-definition");

				if (s->s_nargs == 2)
					return &SEXP_0;

				res = mksexp(S_XOR, 0);
				for (k = 0; k < i; k++)
					res->s_arg[k] = s->s_arg[k];
				for (l = i + 1; l < j; l++)
					res->s_arg[k++] = s->s_arg[l];
				for (l = j + 1; l < s->s_nargs; l++)
					res->s_arg[k++] = s->s_arg[l];
				res->s_nargs = s->s_nargs - 2;

				return res;
			}
		}
	}

	return s;
}

//  s   t           u
// (<< (>> S-Exp N) N)  ->  (& S-Exp (- (<< 1 N) 1))
static struct sexp *
peep_lshiftflatten(struct sexp *s, bool *changed)
{
	struct sexp *t, *u;
	unsigned mask;

	ASSERT(s->s_nargs == 2, "sexpvisit contract");

	t = s->s_arg[0];
	u = s->s_arg[1];

	if (u->s_kind != S_IMMEDIATE)
		return s;

	if (t->s_kind != S_RSHIFT || t->s_nargs != 2)
		return s;

	if (t->s_arg[1]->s_kind != S_IMMEDIATE ||
	    t->s_arg[1]->s_nargs != u->s_nargs)
		return s;

	*changed = true;

	if (u->s_nargs == 8)
		return mksexp(S_AND, 2, t->s_arg[0], &SEXP_FF00);

	mask = 0xffff & ~((1 << u->s_nargs) - 1);
	return mksexp(S_AND, 2, t->s_arg[0], sexp_imm_alloc(mask));
}

//  s   t           u
// (>> (<< S-Exp N) N)  ->  (& S-Exp (- (<< 1 (- 16 N)) 1))
static struct sexp *
peep_rshiftflatten(struct sexp *s, bool *changed)
{
	struct sexp *t, *u;
	unsigned mask;

	ASSERT(s->s_nargs == 2, "sexpvisit contract");

	t = s->s_arg[0];
	u = s->s_arg[1];

	if (u->s_kind != S_IMMEDIATE)
		return s;

	if (t->s_kind != S_LSHIFT || t->s_nargs != 2)
		return s;

	if (t->s_arg[1]->s_kind != S_IMMEDIATE ||
	    t->s_arg[1]->s_nargs != u->s_nargs)
		return s;

	*changed = true;

	if (u->s_nargs == 8)
		return mksexp(S_AND, 2, t->s_arg[0], &SEXP_00FF);

	mask = (1 << (16 - u->s_nargs)) - 1;
	return mksexp(S_AND, 2, t->s_arg[0], sexp_imm_alloc(mask));
}

//  s  t u     v        w x     y
// (| (& S-Exp 0xff00) (& S-Exp 0x00ff)) -> (& S-Exp (y|v))
static struct sexp *
peep_orjoin(struct sexp *s, bool *changed)
{
	struct sexp *t, *u, *v, *w, *x, *y;
	unsigned mask;

	ASSERT(s->s_nargs == 2, "sexpvisit contract");

	t = s->s_arg[0];
	w = s->s_arg[1];

	if (t->s_kind != S_AND || t->s_nargs != 2)
		return s;
	if (w->s_kind != S_AND || w->s_nargs != 2)
		return s;

	u = t->s_arg[0];
	x = w->s_arg[0];
	if (!sexp_eq(u, x))
		return s;

	v = t->s_arg[1];
	y = w->s_arg[1];
	if (v->s_kind != S_IMMEDIATE)
		return s;
	if (y->s_kind != S_IMMEDIATE)
		return s;

	*changed = true;

	mask = v->s_nargs | y->s_nargs;
	if (mask == 0xffff)
		return u;
	else
		return mksexp(S_AND, 2, u, sexp_imm_alloc(mask));
}

//  s  t  u         v  w       x
// (& (| (<< S-Exp1 N) S-Exp2) M) -> (& S-Exp2 M) iff ((1<<N) & M) == 0
static struct sexp *
peep_andorreduce(struct sexp *s, bool *changed)
{
	struct sexp *t, *u, *v, *w, *x;
	unsigned N, M;

	ASSERT(s->s_nargs == 2, "sexpvisit contract");

	t = s->s_arg[0];
	x = s->s_arg[1];

	if (t->s_kind != S_OR || t->s_nargs != 2)
		return s;
	if (x->s_kind != S_IMMEDIATE)
		return s;

	M = x->s_nargs;

	u = t->s_arg[0];
	w = t->s_arg[1];

	// (| S-Exp (<< ...))  ->  (| (<< ...) S-Exp)
	if (u->s_kind != S_LSHIFT && w->s_kind == S_LSHIFT) {
		struct sexp *tmp = u;
		u = w;
		w = tmp;
	}

	if (u->s_kind != S_LSHIFT || u->s_nargs != 2)
		return s;

	v = u->s_arg[1];
	if (v->s_kind != S_IMMEDIATE)
		return s;

	N = v->s_nargs;

	if (((1 << N) & M) == 0) {
		*changed = true;
		return mksexp(S_AND, 2, w, s->s_arg[1]);
	}

	return s;
}

//  s   t       u
// (>> (| ... ) N) -> kill anything in ... that is less than (1<<N)
static struct sexp *
peep_rshiftcancel(struct sexp *s, bool *changed)
{
	struct sexp *t, *u, *newargs[SEXP_MAXARGS] = { 0 };
	unsigned N;

	t = s->s_arg[0];
	u = s->s_arg[1];

	if ((t->s_kind != S_OR && t->s_kind != S_AND) ||
	    u->s_kind != S_IMMEDIATE)
		return s;

	if (t->s_nargs == 0)
		return s;

	N = u->s_nargs;
	memcpy(newargs, t->s_arg, t->s_nargs * sizeof(struct sexp *));

	for (unsigned i = 0; i < t->s_nargs; i++) {
		// (>> inp 8) -> 0
		if (N >= 8 && t->s_arg[i]->s_kind == S_INP) {
			*changed = true;
			newargs[i] = &SEXP_0;
			continue;
		}

		if (t->s_arg[i]->s_kind == S_IMMEDIATE &&
		    t->s_arg[i]->s_nargs != 0 &&
		    t->s_arg[i]->s_nargs < (1u << N)) {
			*changed = true;
			newargs[i] = &SEXP_0;
			continue;
		}
	}

	if (memcmp(newargs, t->s_arg, t->s_nargs * sizeof(struct sexp *))) {
		struct sexp *newt = mksexp(t->s_kind, 0);

		newt->s_nargs = t->s_nargs;
		memcpy(newt->s_arg, newargs, t->s_nargs * sizeof(struct sexp *));
		return mksexp(S_RSHIFT, 2, newt, u);
	}

	return s;
}

// move rra's inwards
static struct sexp *
peep_rra(struct sexp *s, bool *changed)
{
	struct sexp *newargs[SEXP_MAXARGS] = { 0 },
		    *inner = s->s_arg[0],
		    *res;

	ASSERT(s->s_arg[1]->s_kind == S_IMMEDIATE, "x");

	switch (inner->s_kind) {
	case S_OR:
	case S_XOR:
	case S_AND:
	case S_PLUS:
		break;
	default:
		return s;
	}

	*changed = true;
	for (unsigned i = 0; i < inner->s_nargs; i++)
		newargs[i] = mksexp(S_RRA, 2, inner->s_arg[i], s->s_arg[1]);

	res = mksexp(inner->s_kind, 0);
	memcpy(res->s_arg, newargs, inner->s_nargs * sizeof(struct sexp *));
	res->s_nargs = inner->s_nargs;
	return res;
}

// move XOR's inwards
static struct sexp *
peep_xor(struct sexp *s, bool *changed)
{
	struct sexp *imm_s;

	if (s->s_arg[1]->s_kind != S_IMMEDIATE)
		return s;

	switch (s->s_arg[0]->s_kind) {
	case S_OR:
	case S_AND:
	case S_PLUS:
		break;
	default:
		return s;
	}

	imm_s = sexp_imm_alloc(s->s_arg[1]->s_nargs);
	*changed = true;

	s = s->s_arg[0];
	for (unsigned i = 0; i < s->s_nargs; i++)
		s->s_arg[i] = mksexp(S_XOR, 2, s->s_arg[i], imm_s);
	return s;
}

// Special case:
//     o1 s1 i1      i2     o2 s2 i3      i4
// (^ (| (<< Inp1 8) Inp2) (| (<< Inp3 8) Inp4)) =>
// (| (<< (^ Inp1 Inp3) 8) (^ Inp2 Inp4))
static struct sexp *
peep_xorinputs(struct sexp *s, bool *changed)
{
	struct sexp *o1, *o2, *s1, *s2, *i1, *i2, *i3, *i4;

	o1 = s->s_arg[0];
	o2 = s->s_arg[1];

	if (o1->s_kind != S_OR || o2->s_kind != S_OR)
		return s;
	if (o1->s_nargs != 2 || o2->s_nargs != 2)
		return s;

	s1 = o1->s_arg[0];
	s2 = o2->s_arg[0];

	if (s1->s_kind != S_LSHIFT || s2->s_kind != S_LSHIFT)
		return s;
	if (s1->s_nargs != 2 || s2->s_nargs != 2)
		return s;
	if (s1->s_arg[1]->s_kind != S_IMMEDIATE ||
	    s2->s_arg[1]->s_kind != S_IMMEDIATE)
		return s;
	if (s1->s_arg[1]->s_nargs != 8 ||
	    s2->s_arg[1]->s_nargs != 8)
		return s;

	i1 = s1->s_arg[0];
	i2 = o1->s_arg[1];
	i3 = s2->s_arg[0];
	i4 = o2->s_arg[1];

	if (i1->s_kind != S_INP || i2->s_kind != S_INP ||
	    i3->s_kind != S_INP || i4->s_kind != S_INP)
		return s;

	*changed = true;
	return mksexp(S_OR, 2,
	    mksexp(S_LSHIFT, 2,
		mksexp(S_XOR, 2, i1, i3),
		&SEXP_8),
	    mksexp(S_XOR, 2, i2, i4));
}

// move imm ANDs inwards past ORs
static struct sexp *
peep_and(struct sexp *s, bool *changed)
{
	unsigned imm;
	struct sexp *imm_s;

	if (s->s_arg[1]->s_kind != S_IMMEDIATE)
		return s;

	if (s->s_arg[0]->s_kind != S_OR)
		return s;

	imm = s->s_arg[1]->s_nargs;
	imm_s = sexp_imm_alloc(imm);

	*changed = true;
	s = s->s_arg[0];

	for (unsigned i = 0; i < s->s_nargs; i++)
		s->s_arg[i] = mksexp(S_AND, 2, s->s_arg[i], imm_s);
	return s;
}

// concretify what SR results we can
//  s   t
// (sr (+ ...))
static struct sexp *
peep_sr(struct sexp *s, bool *changed)
{
	struct sexp *t;
	bool carry = false;

	t = s->s_arg[0];
	if (t->s_kind != S_PLUS)
		return s;

	for (unsigned i = 0; i < t->s_nargs; i++) {
		if (t->s_arg[i]->s_kind == S_IMMEDIATE &&
		    t->s_arg[i]->s_nargs >= 0x10000) {
			*changed = true;
			//sexpdelidx(t, i);
			carry = true;
		}
	}

	if (carry)
		return mksexp(S_OR, 2, s, &SEXP_1);
	return s;
}

// reduce cmp to == when we only care about equality
static uint16_t expeq_matchimm;
static struct sexp *expeq_matchsexp;
STATIC_PATTERN(expeq_pattern, mksexp(S_AND, 2,
	mksexp(S_SR, 1,
	    mksexp(S_PLUS, 2,
		subsexp(&expeq_matchsexp),
		subimm(&expeq_matchimm))),
	sexp_imm_alloc(SR_Z)));

static struct sexp *
peep_expeq(struct sexp *s, bool *changed)
{

	expeq_matchsexp = NULL;
	expeq_matchimm = 0;

	if (!sexpmatch(expeq_pattern, s))
		return s;

	*changed = true;
	return mksexp(S_LSHIFT, 2,
	    mksexp(S_EQ, 2,
		expeq_matchsexp,
		sexp_imm_alloc( ~(expeq_matchimm - 1) )),
	    &SEXP_1);
}

static struct sexp *shiftimm_matchsexp1,
		   *shiftimm_matchsexp2,
		   *shiftimm_matchsimm;
STATIC_PATTERN(shiftimm_patrx, mksexp(S_RSHIFT, 2,
	mksexp(S_XOR, 2,
	    subsexp(&shiftimm_matchsexp1),
	    subsexp(&shiftimm_matchsexp2)),
	subsexp(&shiftimm_matchsimm)));
STATIC_PATTERN(shiftimm_patra, mksexp(S_RSHIFT, 2,
	mksexp(S_AND, 2,
	    subsexp(&shiftimm_matchsexp1),
	    subsexp(&shiftimm_matchsexp2)),
	subsexp(&shiftimm_matchsimm)));
STATIC_PATTERN(shiftimm_patro, mksexp(S_RSHIFT, 2,
	mksexp(S_OR, 2,
	    subsexp(&shiftimm_matchsexp1),
	    subsexp(&shiftimm_matchsexp2)),
	subsexp(&shiftimm_matchsimm)));
STATIC_PATTERN(shiftimm_patlx, mksexp(S_LSHIFT, 2,
	mksexp(S_XOR, 2,
	    subsexp(&shiftimm_matchsexp1),
	    subsexp(&shiftimm_matchsexp2)),
	subsexp(&shiftimm_matchsimm)));
STATIC_PATTERN(shiftimm_patla, mksexp(S_LSHIFT, 2,
	mksexp(S_AND, 2,
	    subsexp(&shiftimm_matchsexp1),
	    subsexp(&shiftimm_matchsexp2)),
	subsexp(&shiftimm_matchsimm)));
STATIC_PATTERN(shiftimm_patlo, mksexp(S_LSHIFT, 2,
	mksexp(S_OR, 2,
	    subsexp(&shiftimm_matchsexp1),
	    subsexp(&shiftimm_matchsexp2)),
	subsexp(&shiftimm_matchsimm)));

static struct sexp *
peep_shiftimm(struct sexp *s, bool *changed)
{

	shiftimm_matchsexp1 = NULL;
	shiftimm_matchsexp2 = NULL;
	shiftimm_matchsimm = NULL;

	if (sexpmatch(shiftimm_patrx, s) ||
	    sexpmatch(shiftimm_patra, s) ||
	    sexpmatch(shiftimm_patro, s)) {
		if (shiftimm_matchsimm->s_kind != S_IMMEDIATE)
			return s;

		*changed = true;
		return mksexp(s->s_arg[0]->s_kind, 2,
		    mksexp(S_RSHIFT, 2,
			shiftimm_matchsexp1,
			shiftimm_matchsimm),
		    mksexp(S_RSHIFT, 2,
			shiftimm_matchsexp2,
			shiftimm_matchsimm));

	} else if (sexpmatch(shiftimm_patlx, s) ||
	    sexpmatch(shiftimm_patla, s) ||
	    sexpmatch(shiftimm_patlo, s)) {
		if (shiftimm_matchsimm->s_kind != S_IMMEDIATE)
			return s;

		*changed = true;
		return mksexp(s->s_arg[0]->s_kind, 2,
		    mksexp(S_LSHIFT, 2,
			shiftimm_matchsexp1,
			shiftimm_matchsimm),
		    mksexp(S_LSHIFT, 2,
			shiftimm_matchsexp2,
			shiftimm_matchsimm));
	}

	return s;
}

static struct sexp	*orand_sub;
static uint16_t		 orand_im1,
			 orand_im2;
STATIC_PATTERN(orand_pat,
    mksexp(S_OR, 2,
	mksexp(S_AND, 2,
	    subsexp(&orand_sub),
	    subimm(&orand_im1)),
	subimm(&orand_im2)));

// (| (& X im1) im2)
// iff (im1 & im2) == im1
// -> im2
static struct sexp *
peep_orandreduce(struct sexp *s, bool *changed)
{

	orand_sub = NULL;
	orand_im1 = orand_im2 = 0;

	if (sexpmatch(orand_pat, s) && (orand_im1 & orand_im2) == orand_im1) {
		*changed = true;
		return sexp_imm_alloc(orand_im2);
	}

	return s;
}

static struct sexp	*andshift_sub;
static uint16_t		 andshift_im1,
			 andshift_im2;
STATIC_PATTERN(andshift_patl,
    mksexp(S_AND, 2,
	mksexp(S_LSHIFT, 2,
	    subsexp(&andshift_sub),
	    subimm(&andshift_im1)),
	subimm(&andshift_im2)));
STATIC_PATTERN(andshift_patr,
    mksexp(S_AND, 2,
	mksexp(S_RSHIFT, 2,
	    subsexp(&andshift_sub),
	    subimm(&andshift_im1)),
	subimm(&andshift_im2)));

static struct sexp *
peep_andshift(struct sexp *s, bool *changed)
{

	andshift_sub = NULL;
	andshift_im1 = andshift_im2 = 0;

	if (sexpmatch(andshift_patl, s)) {
		if (andshift_sub->s_kind != S_INP ||
		    (andshift_im2 >> andshift_im1) != 0xff)
			return s;

		*changed = true;
		return mksexp(S_LSHIFT, 2,
		    mksexp(S_AND, 2,
			andshift_sub,
			sexp_imm_alloc(andshift_im2 >> andshift_im1)),
		    sexp_imm_alloc(andshift_im1));
	} else if (sexpmatch(andshift_patr, s)) {
		if (andshift_sub->s_kind != S_INP ||
		    (andshift_im2 << andshift_im1) != 0xff00)
			return s;

		*changed = true;
		return mksexp(S_RSHIFT, 2,
		    mksexp(S_AND, 2,
			andshift_sub,
			sexp_imm_alloc((andshift_im2 << andshift_im1) & 0xffff)),
		    sexp_imm_alloc(andshift_im1));
	}

	return s;
}

static struct sexp	*rraflat_sub;
static uint16_t		 rraflat_im1,
			 rraflat_im2;
STATIC_PATTERN(rraflat_pat,
    mksexp(S_RRA, 2,
	mksexp(S_RRA, 2,
	    subsexp(&rraflat_sub),
	    subimm(&rraflat_im1)),
	subimm(&rraflat_im2)));

static struct sexp *
peep_rraflatten(struct sexp *s, bool *changed)
{

	rraflat_sub = NULL;
	rraflat_im1 = rraflat_im2 = 0;

	if (!sexpmatch(rraflat_pat, s))
		return s;

	*changed = true;
	return mksexp(S_RRA, 2,
	    rraflat_sub,
	    sexp_imm_alloc(rraflat_im1 + rraflat_im2));
}

static struct sexp	*rradrop_sub;
static uint16_t		 rradrop_im1,
			 rradrop_im2;

STATIC_PATTERN(rradrop_pand,
    mksexp(S_RRA, 2,
	mksexp(S_AND, 2,
	    subsexp(&rradrop_sub),
	    subimm(&rradrop_im1)),
	subimm(&rradrop_im2)));

STATIC_PATTERN(rradrop_psr,
    mksexp(S_RRA, 2,
	mksexp(S_SR, 1,
	    subsexp(&rradrop_sub)),
	subimm(&rradrop_im1)));

STATIC_PATTERN(rradrop_pinp,
    mksexp(S_RRA, 2,
	subsexp(&rradrop_sub),
	subimm(&rradrop_im1)));

static struct sexp *
peep_rradrop(struct sexp *s, bool *changed)
{

	rradrop_sub = NULL;
	rradrop_im1 = rradrop_im2 = 0;

	if (sexpmatch(rradrop_pand, s)) {
		// (rra (and X im1) im2) -> (>> (and X im1) im2)
		// iff (im1 & 0x8000) == 0
		if (rradrop_im1 & 0x8000)
			return s;

		*changed = true;
		return mksexp(S_RSHIFT, 2,
		    s->s_arg[0],
		    s->s_arg[1]);
	} else if (sexpmatch(rradrop_psr, s)) {
		// (rra (sr X) Y) -> (>> (sr X) Y)

		*changed = true;
		return mksexp(S_RSHIFT, 2,
		    s->s_arg[0],
		    s->s_arg[1]);
	} else if (sexpmatch(rradrop_pinp, s) && rradrop_sub->s_kind == S_INP) {
		// (rra inp im) -> (>> inp im)

		*changed = true;
		return mksexp(S_RSHIFT, 2,
		    s->s_arg[0],
		    s->s_arg[1]);
	}

	return s;
}

typedef struct sexp *(*visiter_cb)(struct sexp *, bool *);

struct sexp *
sexpvisit(enum sexp_kind sk, int nargs, struct sexp *s, visiter_cb cb,
    bool *changed)
{
	struct sexp *newargs[SEXP_MAXARGS] = { 0 };

	ASSERT(s, "non-null");
	if (s->s_kind == S_INP || s->s_kind == S_IMMEDIATE)
		return s;

	ASSERT(s->s_kind != S_SUBSEXP_MATCH, "bogus");

	for (unsigned i = 0; i < s->s_nargs; i++) {
		ASSERT(s->s_arg[i], "non-null");
		newargs[i] = sexpvisit(sk, nargs, s->s_arg[i], cb, changed);
		ASSERT(newargs[i], "non-null");
	}

	if (memcmp(newargs, s->s_arg, s->s_nargs * sizeof(s->s_arg[0]))) {
		unsigned nargs = s->s_nargs;

		s = mksexp(s->s_kind, 0);
		s->s_nargs = nargs;
		memcpy(s->s_arg, newargs, nargs * sizeof(s->s_arg[0]));
	}

	if ((sk == s->s_kind || sk == S_MATCH_ANY) &&
	    ((uns)nargs == s->s_nargs || nargs == -1)) {
		s = cb(s, changed);
		ASSERT(s, "non-null");
	}

	return s;
}

struct sexp *
peephole(struct sexp *s)
{
	bool changed;

	/* Enable this to debug optimizations: */
#if 0
	bool changed1;
	struct sexp *s1;
# define APPLYPEEP(k, n, f) do { \
	changed1 = false;				\
	s1 = sexpvisit(k, n, s, f, &changed1);		\
	if (changed1) {					\
		changed = true;				\
		printf("By " #f ": ");			\
		printsym(s);				\
		printf("->  ");				\
		printsym(s1);				\
		ASSERT(!sexp_eq(s, s1), "changed?");	\
		s = s1;					\
	} else {					\
		ASSERT(s1 == s, "x");			\
	}						\
} while (false)
#else
# define APPLYPEEP(k, n, f) \
	s = sexpvisit(k, n, s, f, &changed)
#endif

	ASSERT(s, "non-null");
	do {
		changed = false;

		APPLYPEEP(S_MATCH_ANY, -1, peep_expfirst);
		APPLYPEEP(S_MATCH_ANY, -1, peep_constreduce);
		APPLYPEEP(S_MATCH_ANY, -1, peep_flatten);
		APPLYPEEP(S_XOR, -1, peep_xorident);
		APPLYPEEP(S_LSHIFT, 2, peep_lshiftflatten);
		APPLYPEEP(S_RSHIFT, 2, peep_rshiftflatten);
		APPLYPEEP(S_OR, 2, peep_orjoin);
		APPLYPEEP(S_AND, 2, peep_andorreduce);
		APPLYPEEP(S_RSHIFT, 2, peep_rshiftcancel);
		APPLYPEEP(S_RRA, 2, peep_rra);
		APPLYPEEP(S_AND, 2, peep_and);
		APPLYPEEP(S_XOR, 2, peep_xor);
		APPLYPEEP(S_SR, 1, peep_sr);
		APPLYPEEP(S_XOR, 2, peep_xorinputs);
		APPLYPEEP(S_AND, 2, peep_expeq);
		APPLYPEEP(S_MATCH_ANY, 2, peep_shiftimm);
		APPLYPEEP(S_LSHIFT, 2, peep_dlshiftflatten);
		APPLYPEEP(S_RSHIFT, 2, peep_drshiftflatten);
		APPLYPEEP(S_OR, 2, peep_orandreduce);
		APPLYPEEP(S_AND, 2, peep_andshift);
		APPLYPEEP(S_RRA, 2, peep_rraflatten);
		APPLYPEEP(S_RRA, 2, peep_rradrop);
	} while (changed);

	return s;
}

struct sexp *
sexp_alloc(enum sexp_kind skind)
{
	struct sexp *r;

	r = malloc(sizeof *r);
	ASSERT(r, "oom");
	r->s_kind = skind;
	return r;
}

struct sexp *
sexp_imm_alloc(uint16_t n)
{
	struct sexp *r;

	r = malloc(sizeof *r);
	ASSERT(r, "oom");
	r->s_kind = S_IMMEDIATE;
	r->s_nargs = n;
	return r;
}

bool
sexp_eq(struct sexp *s, struct sexp *t)
{

	if (s == t)
		return true;

	if (s->s_kind != t->s_kind)
		return false;

	if (s->s_nargs != t->s_nargs)
		return false;

	if (s->s_kind == S_IMMEDIATE || s->s_kind == S_INP)
		return true;

	for (unsigned i = 0; i < s->s_nargs; i++)
		if (!sexp_eq(s->s_arg[i], t->s_arg[i]))
			return false;

	return true;
}

void
sexp_flags(struct sexp *flags, uint16_t *set, uint16_t *clr)
{

	if (flags == NULL)
		return;

	ASSERT(flags->s_nargs == 1, "x");

	switch (flags->s_kind) {
	case S_SR:
	case S_SR_AND:
	case S_SR_RRC:
	case S_SR_RRA:
		break;
	default:
		ASSERT(false, "bad flags sexp: %u", flags->s_kind);
		return;
	}

	ASSERT(flags->s_arg[0]->s_kind == S_IMMEDIATE, "x");
	unsigned res = flags->s_arg[0]->s_nargs;

	switch (flags->s_kind) {
	case S_SR:
		ASSERT(false, "fixme");
		break;
	case S_SR_AND:
		andflags(res, set, clr);
		break;
	case S_SR_RRC:
		ASSERT(false, "fixme");
		break;
	case S_SR_RRA:
		ASSERT(false, "fixme");
		break;
	default:
		ASSERT(false, "x");
		break;
	}
}

struct sexp *
mkinp(unsigned i)
{
	struct sexp *r = sexp_alloc(S_INP);

	r->s_nargs = i;
	return r;
}

struct sexp *
subsexp(struct sexp **out)
{
	struct sexp *res;

	res = mksexp(S_SUBSEXP_MATCH, 0);
	res->s_nargs = SUBSEXP_MATCH_EXP;
	res->s_arg[0] = (void*)out;
	return res;
}

struct sexp *
subimm(uint16_t *out)
{
	struct sexp *res;

	res = mksexp(S_SUBSEXP_MATCH, 0);
	res->s_nargs = SUBSEXP_MATCH_IMM;
	res->s_arg[0] = (void*)out;
	return res;
}

// Similar to sexp_eq, but with wildcard assignment.
bool
sexpmatch(struct sexp *needle, struct sexp *haystack)
{

	if (needle == haystack)
		return true;

	if (needle->s_kind == S_SUBSEXP_MATCH) {
		if (needle->s_nargs == SUBSEXP_MATCH_EXP) {
			*(struct sexp **)needle->s_arg[0] =
			    haystack;
			return true;
		} else if (needle->s_nargs == SUBSEXP_MATCH_IMM) {
			if (haystack->s_kind != S_IMMEDIATE)
				return false;

			*(uint16_t *)needle->s_arg[0] = haystack->s_nargs;
			return true;
		}

		ASSERT(needle->s_nargs == SUBSEXP_MATCH_EXP ||
		    needle->s_nargs == SUBSEXP_MATCH_IMM, "bogus");
		return false;
	}

	if (needle->s_kind != haystack->s_kind)
		return false;

	if (needle->s_nargs != haystack->s_nargs)
		return false;

	if (needle->s_kind == S_IMMEDIATE || needle->s_kind == S_INP)
		return true;

	for (unsigned i = 0; i < needle->s_nargs; i++)
		if (!sexpmatch(needle->s_arg[i], haystack->s_arg[i]))
			return false;

	return true;
}
#endif

void
depcheck(uint16_t addr, unsigned perm)
{

	if (!dep_enabled)
		return;

	if (pageprot[addr >> 8] & perm)
		return;

	printf("DEP: Page 0x%02x is not %s!\n", (uns)addr >> 8,
	    (perm == DEP_W)? "writable" : "executable");
	abort_nodump();
}
