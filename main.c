#include "emu.h"

uint16_t	 pc_start;
uint16_t	 registers[16];
uint8_t		 memory[0x10000];
struct sexp	*register_symbols[16];
GHashTable	*memory_symbols;		// addr -> sexp*
uint64_t	 start;
uint64_t	 insns;
bool		 off;
bool		 unlocked;
bool		 ctrlc;

FILE		*trace;
static bool	 diverged;

static struct sexp SEXP_1 = {.s_kind = S_IMMEDIATE, .s_nargs = 1},
		   SEXP_8 = {.s_kind = S_IMMEDIATE, .s_nargs = 8},
		   SEXP_NEG_1 = {.s_kind = S_IMMEDIATE, .s_nargs = 0xffff};

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
	t->s_nargs = nargs;

	va_start(ap, nargs);
	for (unsigned i = 0; i < nargs; i++) {
		t->s_arg[i] = va_arg(ap, struct sexp *);
		ASSERT(t->s_arg[i] || sk == S_INP || sk == S_IMMEDIATE,
		    "non-null");
	}
	va_end(ap);

	return t;
}

void
print_ips(void)
{
	uint64_t end = now();

	if (end == start)
		end++;

	printf("Approx. %ju instructions per second.\n",
	    (uintmax_t)insns * 1000000 / (end - start));
}

void
init(void)
{

	trace = fopen("msp430_trace.txt", "wb");
	ASSERT(trace, "fopen");
	insns = 0;
	off = unlocked = false;
	start = now();
	memset(memory, 0, sizeof(memory));
	memory_symbols = g_hash_table_new(NULL, NULL);
	ASSERT(memory_symbols, "g_hash");

	memset(registers, 0, sizeof registers);
	for (unsigned reg = 0; reg < 16; reg++)
		register_symbols[reg] = NULL;
}

void
destroy(void)
{

	fflush(trace);
	fclose(trace);
	trace = NULL;
	ASSERT(memory_symbols, "mem_symbol_hash");
	g_hash_table_destroy(memory_symbols);
	memory_symbols = NULL;

	for (unsigned reg = 0; reg < 16; reg++) {
		if (isregsym(reg))
			free(regsym(reg));
		register_symbols[reg] = NULL;
	}
}

#ifndef EMU_CHECK
static void
ctrlc_handler(int s)
{

	(void)s;
	ctrlc = true;
}

int
main(int argc, char **argv)
{
	size_t rd, idx;
	FILE *romfile;

	if (argc < 2) {
		printf("usage: msp430-emu [binaryimage]\n");
		exit(1);
	}

	romfile = fopen(argv[1], "rb");
	ASSERT(romfile, "fopen");

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

	emulate();
	printf("Got CPUOFF, stopped.\n");

	print_ips();

	return 0;
}
#endif

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

void
emulate1(void)
{
	uint16_t instr;

	pc_start = registers[PC];
	ASSERT((registers[PC] & 0x1) == 0, "insn addr unaligned");

	instr = memword(registers[PC]);
#if 0
	if (insns < 59984)
		fprintf(trace, "pc:%04x insn:%04x %04x sr:%04x\n",
		    registers[PC], instr, memword(registers[PC]+2),
		    registers[SR]);
#endif

	if (registers[PC] == 0x44c8) {
#if 0
		fprintf(trace, "pc:44c8 insn:%04x %04x sr:%04x r12:%04x\n",
		    instr, memword(registers[PC]+2), registers[SR],
		    registers[12]);
#endif
		diverged = true;
	}

	// dec r15; jnz -2 busy loop
	if ((instr == 0x831f || instr == 0x533f) &&
	    memword(registers[PC]+2) == 0x23fe) {
		insns += (2ul * registers[15]) + 1;
		registers[15] = 0;

		ASSERT(!isregsym(SR), "TODO");
		registers[SR] &= ~(SR_C | SR_N | SR_V);
		registers[SR] |= SR_Z;
		registers[PC] += 4;
		goto out;
	}

#if 0
	if (instr == 0x4ebd && (isregsym(13) || isregsym(14))) {
		printf("mov @r14+, 0x0(r13)\n");
		printf("r13 sym? %d\n", isregsym(13));
		if (isregsym(13))
			printsym(regsym(13));
		printf("r14 sym? %d\n", isregsym(14));
		if (isregsym(14))
			printsym(regsym(14));
		print_regs();
		print_ips();
	}
#endif

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

	for (unsigned i = 0; i < 16; i++) {
		if (!isregsym(i))
			continue;

		if (sexpdepth(regsym(i), 10)) {
			printf("r%d is *too* symbolic:\n", i);
			printsym(regsym(i));
			off = true;
		}
	}

#if 0
	if (bits(instr, 15, 13) != 0x2000 && insns < 59984) {
		for (unsigned i = 0; i < ((unsigned)registers[PC] - pc_start); i += 2)
			fprintf(trace, "%02x%02x ", membyte(pc_start+i),
			    membyte(pc_start+i+1));
		fprintf(trace, "\n");
	}
#endif

out:
	insns++;
}

void
emulate(void)
{

	registers[PC] = memword(0xfffe);
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

		if (isregsym(PC)) {
			printf("symbolic PC\n");
			abort_nodump();
		}

		if (registers[PC] == 0x0010) {
			if (isregsym(SR)) {
				printf("Symbolic interrupt!!!\nSR =>");
				printsym(regsym(SR));
				abort_nodump();
			}

			// Callgate
			if (registers[SR] & 0x8000) {
				unsigned op = (registers[SR] >> 8) & 0x7f;
				callgate(op);
			}
		}

		if (off)
			break;

		emulate1();

		ASSERT(!isregsym(CG), "CG symbolic");
		ASSERT(registers[CG] == 0, "CG");
		if (registers[SR] & SR_CPUOFF) {
			off = true;
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

	ASSERT(!isregsym(reg), "symbolic reg(%u): can't inc", (uns)reg);
	registers[reg] = (registers[reg] + inc) & 0xffff;
}

void
dec_reg(uint16_t reg, uint16_t bw)
{
	uint16_t inc = 2;

	if (reg != PC && reg != SP && bw)
		inc = 1;

	ASSERT(!isregsym(reg), "symbolic reg(%u): can't dec", (uns)reg);
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

	if (cnd != 0x7 && isregsym(SR)) {
		printf("XXX symbolic branch\nSR: ");
		printsym(regsym(SR));
		abort_nodump();
	}

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
	case 0x5:
		// JGE
		{
		bool N = !!(registers[SR] & SR_N),
		     V = !!(registers[SR] & SR_V);
		shouldjump = ((N ^ V) == 0);
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
	struct sexp *srcsym = NULL, *ressym = NULL, *flagsym = NULL;

	inc_reg(PC, 0);
	load_src(instr, dsrc, As, bw, &srcval, &srckind);

	dstkind = srckind;
	dstval = srcval;

	// Load addressed src values
	switch (srckind) {
	case OP_REG:
		if (isregsym(srcval))
			srcsym = regsym(srcval);
		else
			srcnum = registers[srcval];
		break;
	case OP_MEM:
		if (ismemsym(srcval, bw))
			srcsym = memsym(srcval, bw);
		else {
			if (bw)
				srcnum = membyte(srcval);
			else
				srcnum = memword(srcval);
		}
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
	if (constbits != 0x4 && instr != 0x0)
		illins(instr);

	switch (bits(instr, 9, 7)) {
	case 0x000:
		// RRC
		if (srcsym) {
			if (bw)
				srcsym = peephole(bytemask(srcsym));
			ressym = mksexp(S_RSHIFT, 2, srcsym, &SEXP_1);
			flagsym = mksexp(S_SR_RRC, 1, peephole(ressym));
		} else {
			if (bw)
				srcnum &= 0xff;
			res = srcnum >> 1;

			ASSERT(!isregsym(SR), "TODO");
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
		}
		break;
	case 0x080:
		// SWPB (no flags)
		if (srcsym) {
			struct sexp *lo, *hi;

			hi = mksexp(S_LSHIFT, 2, bytemask(srcsym), &SEXP_8);
			lo = mksexp(S_RSHIFT, 2, srcsym, &SEXP_8);

			ressym = mksexp(S_OR, 2, hi, lo);
		} else
			res = ((srcnum & 0xff) << 8) | (srcnum >> 8);
		break;
	case 0x100:
		// RRA (flags)
		if (srcsym) {
			if (bw)
				srcsym = peephole(bytemask(srcsym));
			ressym = mksexp(S_RRA, 2, srcsym, &SEXP_1);
			flagsym = mksexp(S_SR_RRA, 1, ressym);
		} else {
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
		}
		break;
	case 0x180:
		// SXT (sets flags)
		if (srcsym) {
			ressym = mksexp(S_SXT, 1, srcsym);
			flagsym = mksexp(S_SR_AND, 1, ressym);
		} else {
			if (srcnum & 0x80)
				res = srcnum | 0xff00;
			else
				res = srcnum & 0x00ff;

			andflags(res, &setflags, &clrflags);
		}
		break;
	case 0x200:
		// PUSH (no flags)
		dec_reg(SP, 0);
		dstval = registers[SP];
		dstkind = OP_MEM;

		if (srcsym)
			ressym = srcsym;
		else
			res = srcnum;
		break;
	case 0x280:
		// CALL (no flags)
		if (srcsym) {
			printf("XXX symbolic CALL\n");
			abort_nodump();
		} else {
			// Call [src]
			res = srcnum;
			dstval = PC;
			dstkind = OP_REG;

			// Push PC+1
			dec_reg(SP, 0);
			memwriteword(registers[SP], registers[PC]);
		}
		break;
	default:
		unhandled(instr);
		break;
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
		if (setflags || clrflags) {
			ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
			if (isregsym(SR)) {
				struct sexp *s = sexp_alloc(S_OR), *t;
				s->s_nargs = 2;
				s->s_arg[0] = regsym(SR);
				s->s_arg[1] = sexp_imm_alloc(setflags);
				t = sexp_alloc(S_AND);
				t->s_nargs = 2;
				t->s_arg[0] = s;
				t->s_arg[1] = sexp_imm_alloc(~clrflags & 0x1ff);
				register_symbols[SR] = t;
			} else {
				registers[SR] |= setflags;
				registers[SR] &= ~clrflags;
				registers[SR] &= 0x1ff;
			}
		}

		if (dstkind == OP_REG) {
			ASSERT(res != (uns)-1, "res never set");

			if (bw)
				res &= 0x00ff;

			if (isregsym(dstval))
				register_symbols[dstval] = NULL;

			registers[dstval] = res & 0xffff;
		} else if (dstkind == OP_MEM) {
			if (ismemsym(dstval, bw))
				delmemsyms(dstval, bw);

			if (bw)
				memory[dstval] = (res & 0xff);
			else
				memwriteword(dstval, res);
		} else
			ASSERT(dstkind == OP_FLAGSONLY, "x");
	}
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
	struct sexp *srcsym = NULL, *ressym = NULL, *dstsym = NULL,
		      *flagsym = NULL;

	inc_reg(PC, 0);

	//printf("Src,Ad,bw,As,Dst\n%#04x,%#02x,%#02x,%#02x,%#04x\n", (uns)dsrc,
	//    (uns)Ad, (uns)bw, (uns)As, (uns)ddst);
	load_src(instr, dsrc, As, bw, &srcval, &srckind);
	load_dst(instr, ddst, Ad, &dstval, &dstkind);

	// Load addressed src values
	switch (srckind) {
	case OP_REG:
		if (isregsym(srcval))
			srcsym = regsym(srcval);
		else
			srcnum = registers[srcval];
		break;
	case OP_MEM:
		if (ismemsym(srcval, bw))
			srcsym = memsym(srcval, bw);
		else {
			if (bw)
				srcnum = membyte(srcval);
			else
				srcnum = memword(srcval);
		}
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
		if (isregsym(dstval))
			dstsym = regsym(dstval);
		else
			dstnum = registers[dstval];
		break;
	case OP_MEM:
		if (ismemsym(dstval, bw))
			dstsym = memsym(dstval, bw);
		else {
			if (bw)
				dstnum = membyte(dstval);
			else
				dstnum = memword(dstval);
		}
		break;
	case OP_CONST:
		ASSERT(instr == 0x4303, "nop");
		return;
	default:
		ASSERT(false, "illins");
		break;
	}

	// If either input is symbolic, both are. Put the other value in a
	// temporary symbol.
	if (srcsym && dstsym == NULL) {
		dstsym = sexp_imm_alloc(dstnum);
	} else if (dstsym && srcsym == NULL) {
		srcsym = sexp_imm_alloc(srcnum);
	}

	switch (bits(instr, 15, 12)) {
	case 0x4000:
		// MOV (no flags)
		if (srcsym)
			ressym = srcsym;
		else
			res = srcnum;
		break;
	case 0x5000:
		// ADD (flags)
		if (srcsym) {
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = peephole(mksexp(S_PLUS, 2, srcsym, dstsym));
			flagsym = mksexp(S_SR, 1, ressym);
		} else {
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
		}
		break;
	case 0x6000:
		// ADDC (flags)
		if (srcsym) {
			printf("XXX symbolic ADDC ->SR\n");
			abort_nodump();
		} else {
			if (bw) {
				dstnum &= 0xff;
				srcnum &= 0xff;
			}
			ASSERT(!isregsym(SR), "TODO");
			res = dstnum + srcnum + ((registers[SR] & SR_C) ? 1 : 0);
			addflags(res, bw, &setflags, &clrflags);
			if (bw)
				res &= 0x00ff;
			else
				res &= 0xffff;
		}
		break;
	case 0x8000:
		// SUB (flags)
		if (srcsym) {
			srcsym = mksexp(S_XOR, 2, srcsym, &SEXP_NEG_1);
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = mksexp(S_PLUS, 3, srcsym, dstsym,
			    sexp_imm_alloc(1));
			flagsym = mksexp(S_SR, 1, peephole(ressym));
		} else {
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
		}
		break;
	case 0x9000:
		// CMP (flags)
		dstkind = OP_FLAGSONLY;
		if (srcsym) {
			srcsym = mksexp(S_XOR, 2, srcsym, &SEXP_NEG_1);
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = mksexp(S_PLUS, 3, srcsym, dstsym,
			    sexp_imm_alloc(1));
			flagsym = mksexp(S_SR, 1, peephole(ressym));
		} else {
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
		}
		break;
	case 0xa000:
		// DADD (flags)
		if (srcsym) {
			printf("XXX symbolic DADD ->SR\n");
			abort_nodump();
		} else {
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
	case 0xd000:
		// BIS (no flags)
		if (srcsym) {
			printf("XXX symbolic BIS\n");
			abort_nodump();
		} else
			res = dstnum | srcnum;
		break;
	case 0xe000:
		// XOR (flags)
		if (srcsym) {
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = mksexp(S_XOR, 2, srcsym, dstsym);
			flagsym = mksexp(S_SR_AND, 1, peephole(ressym));
		} else {
			res = dstnum ^ srcnum;
			if (bw)
				res &= 0x00ff;
			andflags(res, &setflags, &clrflags);
		}
		break;
	case 0xf000:
		// AND (flags)
		if (srcsym) {
			if (bw) {
				srcsym = peephole(bytemask(srcsym));
				dstsym = peephole(bytemask(dstsym));
			}
			ressym = mksexp(S_AND, 2, srcsym, dstsym);
			flagsym = mksexp(S_SR_AND, 1, peephole(ressym));
		} else {
			res = dstnum & srcnum;
			if (bw)
				res &= 0x00ff;
			andflags(res, &setflags, &clrflags);
		}
		break;
	default:
		unhandled(instr);
		break;
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
		if (setflags || clrflags) {
			ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
			if (isregsym(SR)) {
				struct sexp *s = sexp_alloc(S_OR), *t;
				s->s_nargs = 2;
				s->s_arg[0] = regsym(SR);
				s->s_arg[1] = sexp_imm_alloc(setflags);
				t = sexp_alloc(S_AND);
				t->s_nargs = 2;
				t->s_arg[0] = s;
				t->s_arg[1] = sexp_imm_alloc(~clrflags & 0x1ff);
				register_symbols[SR] = t;
			} else {
				registers[SR] |= setflags;
				registers[SR] &= ~clrflags;
				registers[SR] &= 0x1ff;
			}
		}

		if (dstkind == OP_REG) {
			ASSERT(res != (unsigned)-1, "res never set");

			if (bw)
				res &= 0x00ff;

			if (isregsym(dstval))
				register_symbols[dstval] = NULL;

			registers[dstval] = res & 0xffff;
		} else if (dstkind == OP_MEM) {
			if (ismemsym(dstval, bw))
				delmemsyms(dstval, bw);

			if (bw)
				memory[dstval] = (res & 0xff);
			else
				memwriteword(dstval, res);
		} else
			ASSERT(dstkind == OP_FLAGSONLY, "x");
	}
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
			extensionword = memword(registers[PC]);
			inc_reg(PC, 0);

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
			extensionword = memword(registers[PC]);
			inc_reg(PC, 0);
			*srckind = OP_MEM;
			ASSERT(!isregsym(instr_decode_src), "symbolic load addr");
			*srcval = (registers[instr_decode_src] + extensionword)
			    & 0xffff;
			break;
		case AS_REGIND:
			*srckind = OP_MEM;
			ASSERT(!isregsym(instr_decode_src), "symbolic load addr");
			*srcval = registers[instr_decode_src];
			break;
		case AS_INDINC:
			*srckind = OP_MEM;

			if (isregsym(instr_decode_src)) {
				printf("symbolic load reg(%u)\n", instr_decode_src);
				printsym(regsym(instr_decode_src));
			}

			ASSERT(!isregsym(instr_decode_src), "symbolic load addr");
			*srcval = registers[instr_decode_src];
			inc_reg(instr_decode_src, bw);
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
		ASSERT(instr == 0x4303, "nop");
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

		extensionword = memword(registers[PC]);
		inc_reg(PC, 0);

		if (instr_decode_dst != SR) {
			ASSERT(!isregsym(instr_decode_dst), "symbolic load addr");
			regval = registers[instr_decode_dst];
		}

		*dstkind = OP_MEM;
		*dstval = (regval + extensionword) & 0xffff;
	}
}

void
_unhandled(const char *f, unsigned l, uint16_t instr)
{

	printf("%s:%u: Instruction: %#04x @PC=%#04x is not implemented\n",
	    f, l, (unsigned)instr, (unsigned)pc_start);
	printf("Raw at PC: ");
	for (unsigned i = 0; i < 6; i++)
		printf("%02x", memory[pc_start+i]);
	printf("\n");
	abort_nodump();
}

void
_illins(const char *f, unsigned l, uint16_t instr)
{

	printf("%s:%u: ILLEGAL Instruction: %#04x @PC=%#04x\n",
	    f, l, (unsigned)instr, (unsigned)pc_start);
	printf("Raw at PC: ");
	for (unsigned i = 0; i < 6; i++)
		printf("%02x", memory[pc_start+i]);
	printf("\n");
	abort_nodump();
}

uint16_t
membyte(uint16_t addr)
{

	ASSERT(!ismemsym(addr, 1), "wrong api for symbolic load");
	return memory[addr];
}

uint16_t
memword(uint16_t addr)
{

	ASSERT((addr & 0x1) == 0, "word load unaligned: %#04x",
	    (unsigned)addr);
	ASSERT(!ismemsym(addr, 0), "wrong api for symbolic load");
	return memory[addr] | ((uint16_t)memory[addr+1] << 8);
}

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

void
abort_nodump(void)
{

	print_regs();
	print_ips();
	exit(1);
}

static void
printmemword(const char *pre, uint16_t addr)
{

	printf("%s", pre);
	if (ismemsym(addr+1, 1))
		printf("??");
	else
		printf("%02x", membyte(addr+1));
	if (ismemsym(addr, 1))
		printf("??");
	else
		printf("%02x", membyte(addr));
}

static void
printreg(unsigned reg)
{

	if (!isregsym(reg)) {
		printf("%04x  ", registers[reg]);
		return;
	}

	printf("????  ");
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

	for (unsigned i = 0; i < 16; i++) {
		if (!isregsym(i))
			continue;

		printf("r%d is symbolic:\n", i);
		printsym(regsym(i));
	}
	printf("\n");
}

uint16_t
sr_flags(void)
{

	ASSERT(!isregsym(SR), "TODO");
	return registers[SR] & (SR_V | SR_CPUOFF | SR_N | SR_Z | SR_C);
}

void
memwriteword(uint16_t addr, uint16_t word)
{

	ASSERT((addr & 0x1) == 0, "word store unaligned: %#04x",
	    (uns)addr);
	memory[addr] = word & 0xff;
	memory[addr+1] = (word >> 8) & 0xff;
}

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
	size_t bufsz;

	switch (op) {
	case 0x0:
#ifndef QUIET
		putchar((char)membyte(argaddr));
#endif
		break;
	case 0x2:
#ifndef QUIET
		printf("Gets (':'-prefix for hex)> ");
		fflush(stdout);
#endif
		getsaddr = memword(argaddr);
		bufsz = (uns)memword(argaddr+2);
		//getsn(getsaddr, bufsz);
		for (unsigned i = 0; i < (unsigned)bufsz - 1; i++) {
			struct sexp *s;

			s = sexp_alloc(S_INP);
			s->s_nargs = i;
			g_hash_table_insert(memory_symbols, ptr(getsaddr+i), s);
		}
		memory[((getsaddr + bufsz) & 0xffff) - 1] = 0;
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

void
getsn(uint16_t addr, uint16_t bufsz)
{
	char *buf;

	ASSERT((size_t)addr + bufsz < 0xffff, "overflow");
	memset(&memory[addr], 0, bufsz);

	if (bufsz <= 1)
		return;

	buf = malloc(2 * bufsz + 2);
	ASSERT(buf, "oom");
	buf[0] = 0;

	if (fgets(buf, 2 * bufsz + 2, stdin) == NULL)
		goto out;

	if (buf[0] != ':')
		strncpy((char*)&memory[addr], buf, bufsz);
	else {
		for (unsigned i = 0; i < bufsz - 1u; i++) {
			unsigned byte;

			if (buf[2*i+1] == 0 || buf[2*i+2] == 0)
				break;

			sscanf(&buf[2*i+1], "%02x", &byte);
			//printf("%02x", byte);
			memory[addr + i] = byte;
		}
	}
	memory[addr + bufsz - 1] = 0;
out:
	free(buf);
}

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
		b2 = peephole(mksexp(S_LSHIFT, 2, b2, 8));
	else
		b2 = sexp_imm_alloc(membyte(addr+1) << 8);

	return mksexp(S_OR, 2, b2, b1);
}

static void
_printsym(struct sexp *sym)
{

	if (sym->s_kind == S_IMMEDIATE) {
		printf("0x%04x", sym->s_nargs);
		return;
	}

	if (sym->s_kind == S_INP) {
		printf("Input[%d]", sym->s_nargs);
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
		printf(">>/");
		ASSERT(sym->s_nargs == 2, "x");
		break;
	default:
		ASSERT(false, "what kind is it? %d", sym->s_kind);
		break;
	}

	for (unsigned i = 0; i < sym->s_nargs; i++) {
		printf(" ");
		_printsym(sym->s_arg[i]);
	}
	printf(")");
}

void
printsym(struct sexp *sym)
{

	if (sym == NULL)
		return;

	_printsym(sym);
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
	high = peephole(mksexp(S_RSHIFT, 2, s, sexp_imm_alloc(8)));

	g_hash_table_insert(memory_symbols, ptr(addr), low);
	g_hash_table_insert(memory_symbols, ptr(addr+1), high);
}

static struct sexp *
peep_constreduce(struct sexp *s, bool *changed)
{

	if (s->s_nargs < 2)
		return s;

	// (x imm imm) -> (x imm)
	for (unsigned n = 3; n > 1; n--) {
		if (s->s_nargs > n && s->s_arg[n-1]->s_kind == S_IMMEDIATE &&
		    s->s_arg[n]->s_kind == S_IMMEDIATE) {
			switch (s->s_kind) {
			case S_PLUS:
				s->s_nargs--;
				s->s_arg[n-1]->s_nargs += s->s_arg[n]->s_nargs;
				*changed = true;
				break;
			case S_OR:
				s->s_nargs--;
				s->s_arg[n-1]->s_nargs |= s->s_arg[n]->s_nargs;
				*changed = true;
				break;
			case S_AND:
				s->s_nargs--;
				s->s_arg[n-1]->s_nargs &= s->s_arg[n]->s_nargs;
				*changed = true;
				break;
			case S_XOR:
				s->s_nargs--;
				s->s_arg[n-1]->s_nargs ^= s->s_arg[n]->s_nargs;
				*changed = true;
				break;
			default:
				break;
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

	switch (s->s_kind) {
	case S_AND:
		if (s->s_arg[1]->s_kind == S_IMMEDIATE &&
		    s->s_arg[1]->s_nargs == 0) {
			// (& x 0) -> 0
			s = s->s_arg[1];
			*changed = true;
		} else if (s->s_arg[1]->s_kind == S_IMMEDIATE &&
		    s->s_arg[1]->s_nargs == 0xffff) {
			// (& x ffff) -> x
			s = s->s_arg[0];
			*changed = true;
		}
		break;
	case S_XOR:
		if (s->s_arg[1]->s_kind == S_IMMEDIATE &&
		    s->s_arg[1]->s_nargs == 0) {
			// (^ x 0) -> x
			s = s->s_arg[0];
			*changed = true;
		}
		break;
	case S_PLUS:
		if (s->s_arg[1]->s_kind == S_IMMEDIATE &&
		    s->s_arg[1]->s_nargs == 0) {
			// (+ x 0) -> x
			s = s->s_arg[0];
			*changed = true;
		}
		break;
	case S_OR:
		if (s->s_arg[1]->s_kind == S_IMMEDIATE &&
		    s->s_arg[1]->s_nargs == 0) {
			// (| x 0) -> x
			s = s->s_arg[0];
			*changed = true;
		} else if (s->s_arg[1]->s_kind == S_IMMEDIATE &&
		    s->s_arg[1]->s_nargs == 0xffff) {
			// (| x ffff) -> ffff
			s = s->s_arg[1];
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
		if (s->s_arg[0]->s_kind == S_IMMEDIATE &&
		    s->s_arg[1]->s_kind != S_IMMEDIATE) {
			struct sexp *t;

			t = s->s_arg[1];
			s->s_arg[1] = s->s_arg[0];
			s->s_arg[0] = t;
			*changed = true;
		}
		break;
	default:
		break;
	}

	return s;
}

static void
sexpflatten(struct sexp *s, unsigned argn)
{
	struct sexp *t;

	t = s->s_arg[argn];
	s->s_arg[argn] = s->s_arg[s->s_nargs - 1];

	for (unsigned i = 0; i < t->s_nargs; i++)
		s->s_arg[s->s_nargs - 1 + i] = t->s_arg[i];

	s->s_nargs += t->s_nargs - 1;
}

static struct sexp *
peep_flatten(struct sexp *s, bool *changed)
{

	ASSERT(s->s_nargs > 0, "huh?");

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
			sexpflatten(s, i);
			return s;
		}
	}

	return s;
}

static void
sexpdelidx(struct sexp *s, unsigned idx)
{

	s->s_arg[idx] = s->s_arg[s->s_nargs - 1];
	s->s_nargs--;
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
				*changed = true;
				ASSERT(i < j, "by-definition");
				sexpdelidx(s, j);
				sexpdelidx(s, i);
				return s;
			}
		}
	}

	return s;
}

typedef struct sexp *(*visiter_cb)(struct sexp *, bool *);

struct sexp *
sexpvisit(enum sexp_kind sk, int nargs, struct sexp *s, visiter_cb cb,
    bool *changed)
{

	ASSERT(s, "non-null");
	if (s->s_kind == S_INP || s->s_kind == S_IMMEDIATE)
		return s;

	for (unsigned i = 0; i < s->s_nargs; i++) {
		ASSERT(s->s_arg[i], "non-null");
		s->s_arg[i] = sexpvisit(sk, nargs, s->s_arg[i], cb, changed);
		ASSERT(s->s_arg[i], "non-null");
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

	ASSERT(s, "non-null");
	do {
		changed = false;
		s = sexpvisit(S_MATCH_ANY, -1, s, peep_expfirst, &changed);
		s = sexpvisit(S_MATCH_ANY, -1, s, peep_constreduce, &changed);
		s = sexpvisit(S_MATCH_ANY, -1, s, peep_flatten, &changed);
		s = sexpvisit(S_XOR, -1, s, peep_xorident, &changed);
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
