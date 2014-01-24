#include "emu.h"

uint16_t	 pc_start;
uint16_t	 registers[16];
uint8_t		 memory[0x10000];
struct symbol	*register_symbols[16];
GHashTable	*memory_symbols;		// addr -> symbol*
uint64_t	 start;
uint64_t	 insns;
bool		 off;
bool		 unlocked;

FILE		*trace;
static bool	 diverged;

static void
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
	memory_symbols = g_hash_table_new_full(NULL, NULL, NULL, free);
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

	emulate();
	printf("Got CPUOFF, stopped.\n");

	print_ips();

	return 0;
}
#endif

void
emulate1(void)
{
	uint16_t instr;

	pc_start = registers[PC];
	ASSERT((registers[PC] & 0x1) == 0, "insn addr unaligned");

	instr = memword(registers[PC]);
	if (insns < 859984 && !diverged)
		fprintf(trace, "pc:%04x insn:%04x sr:%04x\n", registers[PC],
		    instr, registers[SR]);

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
		if (isregsym(PC)) {
			printf("symbolic PC\n");
			abort_nodump();
		}

		if (registers[PC] == 0x0010) {
			if (isregsym(SR)) {
				printf("Symbolic interrupt!!!\nSR =>");
				printsym(stdout, regsym(SR));
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

	ASSERT(!isregsym(reg), "symbolic reg: can't inc");
	registers[reg] = (registers[reg] + inc) & 0xffff;
}

void
dec_reg(uint16_t reg, uint16_t bw)
{
	uint16_t inc = 2;

	if (reg != PC && reg != SP && bw)
		inc = 1;

	ASSERT(!isregsym(reg), "symbolic reg: can't dec");
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
		printf("XXX symbolic branch\n");
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
		 srcval, srcnum, dstval;
	unsigned res = (uns)-1;
	uint16_t setflags = 0,
		 clrflags = 0;
	struct symbol *srcsym = NULL, *ressym = NULL, *flagsym = NULL;

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
			// Could be less symbolic
			if (bw)
				ressym = symsprintf(0, 0x007f,
				    "((%s) & 0xff) >> 1", srcsym->symbolic);
			else
				ressym = symsprintf(0, 0x7fff, "(%s) >> 1",
				    srcsym->symbolic);
			flagsym = symsprintf(0, 0xffff, "sr(%s)",
			    ressym->symbolic);
		} else {
			if (bw)
				srcnum &= 0xff;
			res = srcnum >> 1;
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
			printf("XXX symbolic SWPB\n");
			abort_nodump();
		} else
			res = ((srcnum & 0xff) << 8) | (srcnum >> 8);
		break;
	case 0x100:
		// RRA (flags)
		if (srcsym) {
			printf("XXX symbolic RRA\n");
			abort_nodump();
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
			printf("XXX symbolic SXT\n");
			abort_nodump();
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
			ressym = Xsymdup(srcsym);
		else
			res = srcnum;
		break;
	case 0x280:
		// CALL (no flags)
		if (srcsym) {
			printf("XXX symbolic PUSH\n");
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
		if (flagsym) {
			if (isregsym(SR))
				free(regsym(SR));
			register_symbols[SR] = flagsym;
		}

		if (dstkind == OP_REG) {
			if (isregsym(dstval))
				free(regsym(dstval));

			register_symbols[dstval] = ressym;
		} else if (dstkind == OP_MEM) {
			if (ismemsym(dstval, bw))
				freememsyms(dstval, bw);

			memwritesym(dstval, bw, ressym);
		} else
			ASSERT(dstkind == OP_FLAGSONLY, "x");
	} else {
		if (setflags || clrflags) {
			ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
			if (isregsym(SR)) {
				regsym(SR)->symbol_mask &= ~(setflags | clrflags);
				regsym(SR)->concrete |= setflags;
				regsym(SR)->concrete &= ~clrflags;
				regsym(SR)->symbol_mask &= 0x1ff;
				regsym(SR)->concrete &= 0x1ff;
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

			if (isregsym(dstval)) {
				free(regsym(dstval));
				register_symbols[dstval] = NULL;
			}

			registers[dstval] = res & 0xffff;
		} else if (dstkind == OP_MEM) {
			if (ismemsym(dstval, bw))
				freememsyms(dstval, bw);

			if (bw)
				memory[dstval] = (res & 0xff);
			else
				memwriteword(dstval, res);
		} else
			ASSERT(dstkind == OP_FLAGSONLY, "x");
	}

	for (unsigned i = 0; i < 16; i++) {
		if (isregsym(i) && regsym(i)->symbol_mask == 0) {
			registers[i] = regsym(i)->concrete;
			free(register_symbols[i]);
			register_symbols[i] = NULL;
		}
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
		 dstnum, srcnum /*as a number*/;
	uint16_t setflags = 0,
		 clrflags = 0;
	struct symbol *srcsym = NULL, *ressym = NULL, *dstsym = NULL,
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
	if (srcsym && dstsym == NULL)
		dstsym = tsymsprintf(dstnum, 0x0000, "%#04x", dstnum);
	else if (dstsym && srcsym == NULL)
		srcsym = tsymsprintf(srcnum, 0x0000, "%#04x", srcnum);

	switch (bits(instr, 15, 12)) {
	case 0x4000:
		// MOV (no flags)
		if (srcsym)
			ressym = Xsymdup(srcsym);
		else
			res = srcnum;
		break;
	case 0x5000:
		// ADD (flags)
		if (srcsym) {
			// TODO could be less symbolic
			if (bw)
				ressym = symsprintf(0, 0x00ff,
				    "(((%s) & 0xff) + ((%s) & 0xff)) & 0xff",
				    srcsym->symbolic, dstsym->symbolic);
			else
				ressym = symsprintf(0, 0xffff, "(%s) + (%s)",
				    srcsym->symbolic, dstsym->symbolic);
			flagsym = symsprintf(0, 0xffff, "sr(%s)",
			    ressym->symbolic);
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
			printf("XXX symbolic SUB ->SR\n");
			abort_nodump();
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
		if (srcsym) {
			printf("XXX symbolic CMP ->SR\n");
			abort_nodump();
		} else {
			dstkind = OP_FLAGSONLY;
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
			printf("XXX symbolic XOR -> SR\n");
			abort_nodump();
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
			printf("XXX symbolic AND -> SR\n");
			abort_nodump();
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
		if (flagsym) {
			if (isregsym(SR))
				free(regsym(SR));
			register_symbols[SR] = flagsym;
		}

		if (dstkind == OP_REG) {
			if (isregsym(dstval))
				free(regsym(dstval));

			register_symbols[dstval] = ressym;
		} else if (dstkind == OP_MEM) {
			if (ismemsym(dstval, bw))
				freememsyms(dstval, bw);

			memwritesym(dstval, bw, ressym);
		} else
			ASSERT(dstkind == OP_FLAGSONLY, "x");
	} else {
		if (setflags || clrflags) {
			ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
			if (isregsym(SR)) {
				regsym(SR)->symbol_mask &= ~(setflags | clrflags);
				regsym(SR)->concrete |= setflags;
				regsym(SR)->concrete &= ~clrflags;
				regsym(SR)->symbol_mask &= 0x1ff;
				regsym(SR)->concrete &= 0x1ff;
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

			if (isregsym(dstval)) {
				free(regsym(dstval));
				register_symbols[dstval] = NULL;
			}

			registers[dstval] = res & 0xffff;
		} else if (dstkind == OP_MEM) {
			if (ismemsym(dstval, bw))
				freememsyms(dstval, bw);

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
			*srcval = (registers[instr_decode_src] + extensionword)
			    & 0xffff;
			break;
		case AS_REGIND:
			*srckind = OP_MEM;
			*srcval = registers[instr_decode_src];
			break;
		case AS_INDINC:
			*srckind = OP_MEM;
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

		if (instr_decode_dst != SR)
			regval = registers[instr_decode_dst];

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
	struct symbol *r;

	if (!isregsym(reg)) {
		printf("%04x  ", registers[reg]);
		return;
	}

	r = regsym(reg);
	for (unsigned i = 0; i < 4; i++) {
		uint16_t shift = 12 - (4*i);
		if ((r->symbol_mask >> shift) & 0xf)
			printf("?");
		else
			printf("%01x", (r->concrete >> shift) & 0xf);
	}
	printf("  ");
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
}

uint16_t
sr_flags(void)
{

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
		for (unsigned i = 0; i < bufsz; i++) {
			struct symbol *s;

			s = symsprintf(0, 0xff, "input[%d]", i);
			g_hash_table_insert(memory_symbols, ptr(getsaddr), s);
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

#ifndef AUTO_GETSN
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
#endif

bool
isregsym(uint16_t reg)
{
	struct symbol *r;

	r = register_symbols[reg];
	return (r != NULL);
}

struct symbol *
regsym(uint16_t reg)
{
	struct symbol *r;

	r = register_symbols[reg];
	return r;
}

bool
ismemsym(uint16_t addr, uint16_t bw)
{
	struct symbol *b1, *b2 = NULL;

	b1 = g_hash_table_lookup(memory_symbols, ptr(addr));
	if (bw == 0)
		b2 = g_hash_table_lookup(memory_symbols, ptr(addr + 1));

	return (b1 || b2);
}

struct symbol *
memsym(uint16_t addr, uint16_t bw)
{
	struct symbol *b1, *b2 = NULL;
	uint16_t symmask, concrete;

	b1 = g_hash_table_lookup(memory_symbols, ptr(addr));
	if (bw)
		return b1;

	ASSERT((addr & 1) == 0, "unaligned word read");
	b2 = g_hash_table_lookup(memory_symbols, ptr(addr + 1));

	ASSERT(b1 || b2, "memory is concrete");

	if (b1 == NULL)
		b1 = tsymsprintf(membyte(addr), 0xff, "%02x", membyte(addr));
	else if (b2 == NULL)
		b2 = tsymsprintf(membyte(addr+1), 0xff, "%02x",
		    membyte(addr+1));

	symmask = (b2->symbol_mask << 8) | (b1->symbol_mask & 0xff);
	concrete = (b2->concrete << 8) | (b1->concrete & 0xff);
	return symsprintf(concrete, symmask,
	    "(%s) << 8 | (%s)", b2->symbolic, b1->symbolic);
}

struct symbol *
symsprintf(uint16_t concrete, uint16_t symmask, const char *fmt, ...)
{
	char nfmt[80] = { 0 }, *asp;
	struct symbol *res;
	va_list ap;
	int rc;

	// hackhackhack
	ASSERT(offsetof(struct symbol, symbolic) == 4, "hack");
	sprintf(nfmt, "aaBB%s", fmt);

	va_start(ap, fmt);
	rc = vasprintf(&asp, nfmt, ap);
	va_end(ap);

	ASSERT(rc != -1, "oom");

	res = (struct symbol *)asp; // hackhackhack
	res->concrete = concrete;
	res->symbol_mask = symmask;
	return res;
}

struct symbol *
tsymsprintf(uint16_t concrete, uint16_t symmask, const char *fmt, ...)
{
	static char tsym[84];
	struct symbol *s;
	va_list ap;

	s = (struct symbol *)tsym;
	s->concrete = concrete;
	s->symbol_mask = symmask;

	va_start(ap, fmt);
	vsnprintf(s->symbolic, 80, fmt, ap);
	va_end(ap);

	return s;
}

void
printsym(FILE *f, struct symbol *sym)
{

	if (sym == NULL)
		return;

	fprintf(f, "Symbolic value: %#04x  symbolic bits: %#04x\nSymbolic: %s\n",
	    sym->concrete, sym->symbol_mask, sym->symbolic);
}

void
freememsyms(uint16_t addr, uint16_t bw)
{
	void *v;

	v = g_hash_table_lookup(memory_symbols, ptr(addr));
	if (v)
		free(v);
	if (bw)
		return;
	v = g_hash_table_lookup(memory_symbols, ptr(addr+1));
	if (v)
		free(v);
}

void
memwritesym(uint16_t addr, uint16_t bw, struct symbol *s)
{
	struct symbol *low, *high;

	if (bw)
		s->symbol_mask &= 0xff;

	// Don't write concrete "symbols"
	if (s->symbol_mask == 0) {
		freememsyms(addr, bw);
		if (bw)
			memory[addr] = s->concrete & 0xff;
		else
			memwriteword(addr, s->concrete);
		free(s);
		return;
	}

	if (bw) {
		g_hash_table_insert(memory_symbols, ptr(addr), s);
		return;
	}

	low = symsprintf(s->concrete & 0xff, s->symbol_mask & 0xff,
	    "(%s) & 0xff", s->symbolic);
	high = symsprintf(s->concrete >> 8, s->symbol_mask >> 8,
	    "(%s) >> 8", s->symbolic);
	g_hash_table_insert(memory_symbols, ptr(addr), low);
	g_hash_table_insert(memory_symbols, ptr(addr+1), high);
}
