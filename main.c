#include <sys/cdefs.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#define likely(cond) __builtin_expect ((cond), 1)
#define unlikely(cond) __builtin_expect ((cond), 0)

struct taint {
	unsigned	ntaints;
	uint16_t	addrs[0];
};

uint16_t	 registers[16];
uint8_t		 memory[0x10000];
struct taint	 register_taint[16];
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
	abort(); \
} while (false)

static void	emulate(void);
static uint16_t	load16(uint16_t addr);

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

	emulate();

	return 0;
}

static void
emulate(void)
{

	registers[PC] = load16(0xfffe);
	printf("Starting PC: %#04x\n", (unsigned)registers[PC]);
}

static uint16_t
load16(uint16_t addr)
{

	ASSERT((addr & 0x1) == 0, "word load unaligned: %#04x",
	    (unsigned)addr);
	return memory[addr] | ((uint16_t)memory[addr+1] << 8);
}
