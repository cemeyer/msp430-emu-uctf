#include <sys/cdefs.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#define likely(cond) __builtin_expect ((cond), 1)
#define unlikely(cond) __builtin_expect ((cond), 0)

struct taint {
	unsigned	ntaints;
	uint16_t	addrs[0];
};

uint16_t	 pc_start;
uint16_t	 registers[16];
uint8_t		 memory[0x10000];
struct taint	*register_taint[16];
GHashTable	*memory_taint;		// addr -> struct taint

#define PC 0
#define SP 1
#define SR 2
#define CG 3

#define AS_REG    0x00
#define AS_IDX    0x10
#define AS_REGIND 0x20
#define AS_INDINC 0x30

#define AS_R2_ABS 0x10
#define AS_R2_4   0x20
#define AS_R2_8   0x30

#define AS_R3_0   0x00
#define AS_R3_1   0x10
#define AS_R3_2   0x20
#define AS_R3_NEG 0x30

#define AD_REG    0x00
#define AD_IDX    0x80

#define AD_R2_ABS 0x80

#define SR_CPUOFF 0x0010

enum operand_kind {
	OP_REG,
	OP_MEM,
	OP_CONST,
};

typedef unsigned int uns;

#define ASSERT(cond, args...) do { \
	if (likely(!!(cond))) \
		break; \
	printf("%s:%u: ASSERT %s failed: ", __FILE__, __LINE__, #cond); \
	printf(args); \
	printf("\n"); \
	abort_nodump(); \
} while (false)

static void	abort_nodump(void);
static void	emulate(void);
static uint16_t	memword(uint16_t addr);
static void	mem2reg(uint16_t addr, unsigned reg);
static void	reg2mem(unsigned reg, uint16_t addr);
static uint16_t	bits(uint16_t v, unsigned max, unsigned min);
static void	copytaint(struct taint **dest, const struct taint *src);
static void	unhandled(uint16_t instr);
static void	illins(uint16_t instr);
static struct taint	*newtaint(void);
static void	inc_reg(uint16_t reg, uint16_t bw);
static void	print_regs(void);

static void	handle_jump(uint16_t instr);
static void	handle_single(uint16_t instr);
static void	handle_double(uint16_t instr);

static void	load_src(uint16_t instr, uint16_t instr_decode_src,
			 uint16_t As, uint16_t bw, uint16_t *srcval,
			 enum operand_kind *srckind);
static void	load_dst(uint16_t instr, uint16_t instr_decode_dst,
			 uint16_t Ad, uint16_t *dstval,
			 enum operand_kind *dstkind);

int
main(int argc, char **argv)
{
	size_t rd, idx;
	FILE *romfile;

	if (argc < 2) {
		printf("usage: msp430-emu [binaryimage]\n");
		exit(1);
	}

	memory_taint = g_hash_table_new_full(NULL, NULL, NULL, free);
	ASSERT(memory_taint, "g_hash");

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

	for (unsigned reg = 0; reg < 16; reg++)
		register_taint[reg] = newtaint();

	emulate();

	return 0;
}

static void
emulate(void)
{
	uint16_t instr;

	mem2reg(0xfffe, PC);
	printf("Initial register state:\n");
	print_regs();
	printf("============================================\n\n");

	while (true) {
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

static void
inc_reg(uint16_t reg, uint16_t bw)
{
	uint16_t inc = 2;

	if (reg != PC && reg != SP && bw)
		inc = 1;

	registers[reg] = (registers[reg] + inc) & 0xffff;
}

static void
handle_jump(uint16_t instr)
{

	unhandled(instr);
}

static void
handle_single(uint16_t instr)
{

	unhandled(instr);
}

static void
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

static void
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

static void
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

static struct taint *
newtaint(void)
{
	struct taint *res = malloc(sizeof(struct taint));
	ASSERT(res, "malloc");
	res->ntaints = 0;
	return res;
}

static void
unhandled(uint16_t instr)
{

	printf("Instruction: %#04x @PC=%#04x is not implemented\n",
	    (unsigned)instr, (unsigned)pc_start);
	abort_nodump();
}

static void
illins(uint16_t instr)
{

	printf("ILLEGAL Instruction: %#04x @PC=%#04x\n", (unsigned)instr,
	    (unsigned)pc_start);
	abort_nodump();
}

static uint16_t
memword(uint16_t addr)
{

	ASSERT((addr & 0x1) == 0, "word load unaligned: %#04x",
	    (unsigned)addr);
	return memory[addr] | ((uint16_t)memory[addr+1] << 8);
}

static void
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

static void
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

static uint16_t
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

static void
copytaint(struct taint **dest, const struct taint *src)
{
	size_t tsize;

	ASSERT(src->ntaints > 0, "copytaint");

	tsize = sizeof(struct taint) + (src->ntaints * sizeof(src->addrs[0]));
	*dest = realloc(*dest, tsize);
	ASSERT(*dest, "realloc");
	memcpy(*dest, src, tsize);
}

static void
abort_nodump(void)
{

	print_regs();
	exit(1);
}

static void
print_regs(void)
{

	printf("pc  %04x  sp  %04x  sr  %04x  cg  0000\n", (uns)registers[PC],
	    (uns)registers[SP], (uns)registers[SR]);
	for (unsigned i = 4; i < 16; i += 4)
		printf("r%02u %04x  r%02u %04x  r%02u %04x  r%02u %04x\n", i,
		    (uns)registers[i], i + 1, (uns)registers[i+1], i + 2,
		    (uns)registers[i+2], i + 3, (uns)registers[i+3]);
}
