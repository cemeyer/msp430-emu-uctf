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

uint16_t	 registers[16];
uint8_t		 memory[0x10000];
struct taint	*register_taint[16];
GHashTable	*memory_taint;		// addr -> struct taint

#define PC 0
#define SP 1
#define SR 2
#define CG 3

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
static struct taint	*newtaint(void);

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
	printf("Starting PC: %#04x\n", (unsigned)registers[PC]);

	while (true) {
		ASSERT((registers[PC] & 0x1) == 0, "insn addr unaligned");

		instr = memword(registers[PC]);

		switch (bits(instr, 15, 13)) {
		case 0:
			// single-operand arithmetic
			unhandled(instr);
			break;
		case 0x2000:
			// jumps
			unhandled(instr);
			break;
		default:
			// 2-operand arithmetic
			unhandled(instr);
			break;
		}
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
	    (unsigned)instr, (unsigned)registers[PC]);
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

	exit(1);
}
