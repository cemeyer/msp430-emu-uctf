#include "emu.h"

uint16_t	 pc_start;
uint16_t	 registers[16];
uint8_t		 memory[0x10000];
struct taint	*register_taint[16];
GHashTable	*memory_taint;		// addr -> struct taint

void
init(void)
{

	memory_taint = g_hash_table_new_full(NULL, NULL, NULL, free);
	ASSERT(memory_taint, "g_hash");

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

	idx = 0;
	while (true) {
		rd = fread(memory, 1, sizeof(memory) - idx, romfile);
		if (rd == 0)
			break;
		idx += rd;
	}
	printf("Loaded %zu words from image.\n", idx);

	fclose(romfile);

	// XXX set memory taints
	// XXX or just auto-set on getsn()

	init();
	emulate();

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
}

void
emulate(void)
{

	mem2reg(0xfffe, PC);
	printf("Initial register state:\n");
	print_regs();
	printf("============================================\n\n");

	while (true) {
		emulate1();

		// DDD
		print_regs();
		printf("\n");

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
handle_jump(uint16_t instr)
{

	unhandled(instr);
}

void
handle_single(uint16_t instr)
{

	unhandled(instr);
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

	inc_reg(PC, 0);

	load_src(instr, dsrc, As, bw, &srcval, &srckind);
	load_dst(instr, ddst, Ad, &dstval, &dstkind);

	switch (bits(instr, 15, 12)) {
	case 0x4000:
		// MOV
		//printf("DDD MOV(src:%x, dst: %x, as:%x, ad:%x, b/w:%x)\n",
		//    (uns)dsrc, (uns)ddst, (uns)As, (uns)Ad, (uns)bw);

		if (dstkind == OP_MEM) {
			if (bw) {
			} else {
				ASSERT((dstval & 0x1) == 0, "word store "
				    "unaligned: %#04x", (unsigned)dstval);
			}

			unhandled(instr);
		} else if (dstkind == OP_REG) {
			if (srckind == OP_MEM) {
				printf("DDD MOV @%#04x (%#04x), r%d\n",
				    (uns)srcval, memword(srcval), (uns)dstval);
				mem2reg(srcval, dstval);
			} else
				unhandled(instr);

			if (bw)
				registers[dstval] &= 0x00ff;
		} else
			unhandled(instr);

		break;
	default:
		unhandled(instr);
		break;
	}
}

// R0 only supports AS_IDX, AS_INDINC (inc 2), AD_IDX.
// R2 only supports AS_R2_*, AD_R2_ABS.
// R3 only supports As (no Ad).

void
load_src(uint16_t instr, uint16_t instr_decode_src, uint16_t As, uint16_t bw,
    uint16_t *srcval, enum operand_kind *srckind)
{

	if (instr_decode_src == PC) {
		if (As == AS_REGIND)
			illins(instr);
	}

	switch (instr_decode_src) {
	case 2:
		unhandled(instr);
		break;
	case 3:
		unhandled(instr);
		break;
	default:
		switch (As) {
		case AS_INDINC:
			*srckind = OP_MEM;
			*srcval = registers[instr_decode_src];
			inc_reg(instr_decode_src, bw);
			break;
		default:
			unhandled(instr);
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

	if (instr_decode_dst == 3)
		illins(instr);

	if (Ad == AD_REG) {
		*dstkind = OP_REG;
		*dstval = instr_decode_dst;
	} else {
		uint16_t regval = 0, extensionword;

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
unhandled(uint16_t instr)
{

	printf("Instruction: %#04x @PC=%#04x is not implemented\n",
	    (unsigned)instr, (unsigned)pc_start);
	abort_nodump();
}

void
illins(uint16_t instr)
{

	printf("ILLEGAL Instruction: %#04x @PC=%#04x\n", (unsigned)instr,
	    (unsigned)pc_start);
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
	if (memtaint)
		copytaint(&register_taint[reg], memtaint);
	else {
		free(register_taint[reg]);
		register_taint[reg] = newtaint();
	}

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

	ASSERT(src->ntaints > 0, "copytaint");

	tsize = sizeof(struct taint) + (src->ntaints * sizeof(src->addrs[0]));
	*dest = realloc(*dest, tsize);
	ASSERT(*dest, "realloc");
	memcpy(*dest, src, tsize);
}

void
abort_nodump(void)
{

	print_regs();
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
}
