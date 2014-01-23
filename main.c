#include "emu.h"

uint16_t	 pc_start;
uint16_t	 registers[16];
uint8_t		 memory[0x10000];
struct taint	*register_taint[16];
GHashTable	*memory_taint;		// addr -> struct taint
uint64_t	 start;
uint64_t	 insns;

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

	insns = 0;
	start = now();
	memset(memory, 0, sizeof(memory));
	memory_taint = g_hash_table_new_full(NULL, NULL, NULL, free);
	ASSERT(memory_taint, "g_hash");

	memset(registers, 0, sizeof registers);
	for (unsigned reg = 0; reg < 16; reg++)
		register_taint[reg] = newtaint();
}

void
destroy(void)
{

	ASSERT(memory_taint, "mem_taint_hash");
	g_hash_table_destroy(memory_taint);
	memory_taint = NULL;

	for (unsigned reg = 0; reg < 16; reg++) {
		ASSERT(register_taint[reg], "reg_taint");
		free(register_taint[reg]);
		register_taint[reg] = NULL;
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
	ASSERT(memword(0x10) == 0x4130, "No callgate at 0x10??: Instead: %04x",
	    memword(0x10));

	fclose(romfile);

	// XXX set memory taints
	// XXX or just auto-set on getsn()

	emulate();

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

	insns++;
}

void
emulate(void)
{

	mem2reg(0xfffe, PC);
	printf("Initial register state:\n");
	print_regs();
	printf("============================================\n\n");

	while (true) {
		if (registers[PC] == 0x0010) {
			// Callgate
			if (registers[SR] & 0x8000) {
				unsigned op = (registers[SR] >> 8) & 0x7f;
				callgate(op);
			}
		}

		emulate1();

		ASSERT(registers[CG] == 0, "CG");
		if (registers[SR] & SR_CPUOFF) {
			printf("Got CPUOFF, stopped.\n");
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

	registers[reg] = (registers[reg] + inc) & 0xffff;
}

void
dec_reg(uint16_t reg, uint16_t bw)
{
	uint16_t inc = 2;

	if (reg != PC && reg != SP && bw)
		inc = 1;

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
	struct taint *taintsrc = NULL;
	unsigned res = 0x10000;
	uint16_t setflags = 0,
		 clrflags = 0;
	enum taint_apply ta = t_ignore;

	inc_reg(PC, 0);
	load_src(instr, dsrc, As, bw, &srcval, &srckind);

	// Load addressed src values
	switch (srckind) {
	case OP_REG:
		taintsrc = register_taint[srcval];
		srcnum = registers[srcval];
		break;
	case OP_MEM:
		taintsrc = g_hash_table_lookup(memory_taint,
		    GINT_TO_POINTER(srcval & 0xfffe));
		if (bw)
			srcnum = memory[srcval];
		else
			srcnum = memword(srcval);
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
	case 0x080:
		// SWPB (no flags)
		res = ((srcnum & 0xff) << 8) | (srcnum >> 8);
		dstval = srcval;
		dstkind = srckind;
		break;
	case 0x180:
		// SXT (sets flags)
		if (srcnum & 0x80)
			res = srcnum | 0xff00;
		else
			res = srcnum & 0x00ff;

		dstval = srcval;
		dstkind = srckind;
		andflags(res, &setflags, &clrflags);
		break;
	case 0x200:
		// PUSH (no flags)
		ta = t_copy;
		res = srcnum;
		dec_reg(SP, 0);
		dstval = registers[SP];
		dstkind = OP_MEM;
		break;
	case 0x280:
		// CALL (no flags)
		ta = t_copy;

		// Call [src]
		res = srcnum;
		dstval = PC;
		dstkind = OP_REG;

		// Push PC+1
		dec_reg(SP, 0);
		memwriteword(registers[SP], registers[PC]);
		copytaintmem(registers[SP], register_taint[PC]);
		break;
	default:
		unhandled(instr);
		break;
	}

	ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
	registers[SR] |= setflags;
	registers[SR] &= ~clrflags;

	if (dstkind == OP_REG) {
		ASSERT(res != 0x10000, "res never set");

		if (bw)
			res &= 0x00ff;

		registers[dstval] = res & 0xffff;
		if (ta == t_add)
			addtaint(&register_taint[dstval], taintsrc);
		else if (ta == t_copy)
			copytaint(&register_taint[dstval], taintsrc);
	} else if (dstkind == OP_MEM) {
		if (bw) {
			if (ta == t_copy)
				ta = t_add;
			memory[dstval] = res & 0xff;
		} else
			memwriteword(dstval, res);

		if (ta == t_add)
			addtaintmem(dstval & 0xfffe, taintsrc);
		else if (ta == t_copy)
			copytaintmem(dstval, taintsrc);
	} else
		ASSERT(dstkind == OP_FLAGSONLY, "x");
}

void
handle_double(uint16_t instr)
{
	enum operand_kind srckind, dstkind;
	struct taint *taintsrc = NULL;
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
	enum taint_apply ta = t_ignore;

	inc_reg(PC, 0);

	//printf("Src,Ad,bw,As,Dst\n%#04x,%#02x,%#02x,%#02x,%#04x\n", (uns)dsrc,
	//    (uns)Ad, (uns)bw, (uns)As, (uns)ddst);
	load_src(instr, dsrc, As, bw, &srcval, &srckind);
	load_dst(instr, ddst, Ad, &dstval, &dstkind);

	// Load addressed src values
	switch (srckind) {
	case OP_REG:
		taintsrc = register_taint[srcval];
		srcnum = registers[srcval];
		break;
	case OP_MEM:
		taintsrc = g_hash_table_lookup(memory_taint,
		    GINT_TO_POINTER(srcval & 0xfffe));
		if (bw)
			srcnum = memory[srcval];
		else
			srcnum = memword(srcval);
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
		dstnum = registers[dstval];
		break;
	case OP_MEM:
		if (bw)
			dstnum = memory[dstval];
		else
			dstnum = memword(dstval);
		break;
	default:
		ASSERT(false, "illins");
		break;
	}

	switch (bits(instr, 15, 12)) {
	case 0x4000:
		// MOV (no flags)
		ta = t_copy;
		res = srcnum;
		break;
	case 0x5000:
		// ADD (flags)
		ta = t_add;
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
		break;
	case 0x8000:
		// SUB (flags)
		ta = t_add;
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
		break;
	case 0x9000:
		// CMP (flags)
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
		break;
	case 0xd000:
		// BIS (no flags)
		ta = t_add;
		res = dstnum | srcnum;
		break;
	case 0xf000:
		// AND (flags)
		ta = t_add;
		res = dstnum & srcnum;
		if (bw)
			res &= 0x00ff;
		andflags(res, &setflags, &clrflags);
		break;
	default:
		unhandled(instr);
		break;
	}

	ASSERT((setflags & clrflags) == 0, "set/clr flags shouldn't overlap");
	registers[SR] |= setflags;
	registers[SR] &= ~clrflags;

	if (dstkind == OP_REG) {
		ASSERT(res != (unsigned)-1, "res never set");

		if (bw)
			res &= 0x00ff;

		registers[dstval] = res & 0xffff;
		if (ta == t_add)
			addtaint(&register_taint[dstval], taintsrc);
		else if (ta == t_copy)
			copytaint(&register_taint[dstval], taintsrc);
	} else if (dstkind == OP_MEM) {
		if (bw) {
			if (ta == t_copy)
				ta = t_add;
			memory[dstval] = res & 0xff;
		} else
			memwriteword(dstval, res);

		if (ta == t_add)
			addtaintmem(dstval & 0xfffe, taintsrc);
		else if (ta == t_copy)
			copytaintmem(dstval, taintsrc);
	} else
		ASSERT(dstkind == OP_FLAGSONLY, "x");
}

// R0 only supports AS_IDX, AS_INDINC (inc 2), AD_IDX.
// R2 only supports AS_R2_*, AD_R2_ABS (and direct for both).
// R3 only supports As (no Ad).

void
load_src(uint16_t instr, uint16_t instr_decode_src, uint16_t As, uint16_t bw,
    uint16_t *srcval, enum operand_kind *srckind)
{
	uint16_t extensionword;

	if (instr_decode_src == PC) {
		if (As == AS_REGIND)
			illins(instr);
	}

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

	if (instr_decode_dst == CG)
		illins(instr);

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

struct taint *
newtaint(void)
{
	struct taint *res = malloc(sizeof(struct taint));
	ASSERT(res, "malloc");
	res->ntaints = 0;
	return res;
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
memword(uint16_t addr)
{

	ASSERT((addr & 0x1) == 0, "word load unaligned: %#04x",
	    (unsigned)addr);
	return memory[addr] | ((uint16_t)memory[addr+1] << 8);
}

void
mem2reg(uint16_t addr, unsigned reg)
{
	struct taint *memtaint;
	uint16_t val;

	ASSERT(reg < 16, "reg");

	val = memword(addr);

	memtaint = g_hash_table_lookup(memory_taint, GINT_TO_POINTER(addr));
	copytaint(&register_taint[reg], memtaint);

	registers[reg] = val;
}

void
reg2mem(unsigned reg, uint16_t addr)
{

	ASSERT(reg < 16, "reg");
	ASSERT((addr & 0x1) == 0, "word store unaligned: %#04x",
	    (unsigned)addr);

	if (register_taint[reg]->ntaints > 0) {
		struct taint *memtaint = g_hash_table_lookup(memory_taint,
		    GINT_TO_POINTER(addr));

		if (memtaint)
			g_hash_table_remove(memory_taint,
			    GINT_TO_POINTER(addr));
		else
			memtaint = newtaint();

		copytaint(&memtaint, register_taint[reg]);
		g_hash_table_insert(memory_taint, GINT_TO_POINTER(addr),
		    memtaint);
	} else {
		g_hash_table_remove(memory_taint, GINT_TO_POINTER(addr));
	}

	memory[addr] = registers[reg] & 0xff;
	memory[addr+1] = (registers[reg] >> 8) & 0xff;
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
copytaint(struct taint **dest, const struct taint *src)
{
	size_t tsize;

	if (src == NULL || src->ntaints == 0) {
		(*dest)->ntaints = 0;
		return;
	}

	tsize = sizeof(struct taint) + (src->ntaints * sizeof(uint16_t));
	*dest = realloc(*dest, tsize);
	ASSERT(*dest, "realloc");
	memcpy(*dest, src, tsize);
}

void
copytaintmem(uint16_t addr, const struct taint *src)
{
	struct taint *mt;
	size_t tsize;

	g_hash_table_remove(memory_taint, GINT_TO_POINTER(addr));

	if (src == NULL || src->ntaints == 0)
		return;

	tsize = sizeof(struct taint) + (src->ntaints * sizeof(uint16_t));
	mt = malloc(tsize);
	ASSERT(mt, "oom");
	memcpy(mt, src, tsize);

	g_hash_table_insert(memory_taint, GINT_TO_POINTER(addr), mt);
}

void
abort_nodump(void)
{

	print_regs();
	print_ips();
	exit(1);
}

void
print_regs(void)
{

	printf("pc  %04x  sp  %04x  sr  %04x  cg  0000\n", (uns)registers[PC],
	    (uns)registers[SP], (uns)registers[SR]);
	for (unsigned i = 4; i < 16; i += 4)
		printf("r%02u %04x  r%02u %04x  r%02u %04x  r%02u %04x\n", i,
		    (uns)registers[i], i + 1, (uns)registers[i+1], i + 2,
		    (uns)registers[i+2], i + 3, (uns)registers[i+3]);
	printf("stack:");
	for (unsigned i = 0; i < 4; i++)
		printf("  %04x", (uns)memword((registers[SP] & 0xfffe) + 2*i));
	printf("\n      ");
	for (unsigned i = 4; i < 8; i++)
		printf("  %04x", (uns)memword((registers[SP] & 0xfffe) + 2*i));
	printf("\n");
}

void
taint_mem(uint16_t addr)
{
	struct taint *mt;

	mt = malloc(sizeof(struct taint) + sizeof(uint16_t));
	ASSERT(mt, "oom");
	mt->ntaints = 1;
	mt->addrs[0] = addr;

	g_hash_table_insert(memory_taint, GINT_TO_POINTER(addr), mt);
}

bool
regtainted(uint16_t reg, uint16_t addr)
{

	for (unsigned i = 0; i < register_taint[reg]->ntaints; i++)
		if (register_taint[reg]->addrs[i] == addr)
			return true;
	return false;
}

bool
regtaintedexcl(uint16_t reg, uint16_t addr)
{

	return regtainted(reg, addr) && (register_taint[reg]->ntaints == 1);
}

void
addtaint(struct taint **dst, struct taint *src)
{
	unsigned total = (*dst)->ntaints;

	if (src == NULL)
		return;

	if (src->ntaints == 0)
		return;

	total += src->ntaints;
	*dst = realloc(*dst, sizeof(**dst) + total*sizeof(uint16_t));
	ASSERT(*dst, "oom");

	for (unsigned i = 0; i < src->ntaints; i++) {
		uint16_t taddr = src->addrs[i];
		bool dupe = false;

		for (unsigned j = 0; j < (*dst)->ntaints; j++) {
			if ((*dst)->addrs[j] == taddr) {
				dupe = true;
				break;
			}
		}

		if (!dupe) {
			(*dst)->addrs[(*dst)->ntaints] = taddr;
			(*dst)->ntaints += 1;
		}
	}
}

void
addtaintmem(uint16_t addr, struct taint *src)
{
	unsigned total = 0;
	struct taint *mt;

	ASSERT((addr & 1) == 0, "aligned");

	if (src == NULL)
		return;

	if (src->ntaints == 0)
		return;

	mt = g_hash_table_lookup(memory_taint, GINT_TO_POINTER(addr));
	if (mt) {
		g_hash_table_remove(memory_taint, GINT_TO_POINTER(addr));
		total = mt->ntaints;
	} else
		mt = newtaint();

	total += src->ntaints;
	mt = realloc(mt, sizeof(*mt) + total*sizeof(uint16_t));
	ASSERT(mt, "oom");

	for (unsigned i = 0; i < src->ntaints; i++) {
		uint16_t taddr = src->addrs[i];
		bool dupe = false;

		for (unsigned j = 0; j < mt->ntaints; j++) {
			if (mt->addrs[j] == taddr) {
				dupe = true;
				break;
			}
		}

		if (!dupe) {
			mt->addrs[mt->ntaints] = taddr;
			mt->ntaints += 1;
		}
	}

	g_hash_table_insert(memory_taint, GINT_TO_POINTER(addr), mt);
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

	return ((uint64_t)1000000 * ts.tv_sec + (ts.tv_nsec / 1000));
}

void
callgate(unsigned op)
{
	uint16_t argaddr = registers[SP] + 8,
		 getsaddr;
	char *buf;
	size_t bufsz;

	switch (op) {
	case 0x0:
		putchar((char)memory[argaddr]);
		break;
	case 0x2:
		printf("Gets (':'-prefix for hex)> ");
		fflush(stdout);

		getsaddr = memword(argaddr);
		bufsz = (uns)memword(argaddr+2);

		buf = malloc(2 * bufsz + 2);
		ASSERT(buf, "oom");
		buf[0] = 0;

		if (fgets(buf, 2 * bufsz + 2, stdin) == NULL) {
			free(buf);
			memory[getsaddr] = 0;
			break;
		}

		if (buf[0] != ':')
			strncpy((char*)&memory[getsaddr], buf, bufsz);
		else {
			for (unsigned i = 0; i < bufsz - 1; i++) {
				unsigned byte;

				if (buf[2*i+1] == 0 || buf[2*i+2] == 0)
					break;

				sscanf(&buf[2*i+1], "%02x", &byte);
				//printf("%02x", byte);
				memory[getsaddr + i] = byte;
			}
		}
		memory[getsaddr + bufsz - 1] = 0;
		free(buf);
		break;
	case 0x7f:
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

	printf("The lock opens; you win!\n");
	exit(0);
}
