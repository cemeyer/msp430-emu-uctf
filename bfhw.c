#include <sys/time.h>

#include "emu.h"

#define PROFILE_BFHW 0

char rom[0x10000];

char fastload[0x10000];
char fastregisters[16*2];

#define ATTEMPT_LEN 5
uint8_t attempt[ATTEMPT_LEN];

bool fastrom;

void
getsn(uint16_t addr, uint16_t bufsz)
{

	if (!fastrom) {
		memcpy(fastload, memory, sizeof(fastload));
		memcpy(fastregisters, registers, sizeof(fastregisters));
		fastrom = true;
		off = true;
		return;
	}

	(void)bufsz;
	memcpy(&memory[addr], attempt, ATTEMPT_LEN);
}

unsigned attemptlimit;

FILE *urandom;

#if 0
void
memdiff(uint8_t *memory, uint8_t *rom)
{

	printf("Different pages: ");
	for (unsigned i = 0; i < 256; i++) {
		bool eq = true;
		for (unsigned j = 0; j < 256; j++) {
			if (memory[i*256 + j] != rom[i*256 + j]) {
				eq = false;
				break;
			}
		}

		if (!eq)
			printf("0x%x, ", i);
	}
	printf("\n");
}
#endif

#if PROFILE_BFHW
FILE *profile;
#define NSPOTS (1024*32)
#define NINSTR 8
char hotspots[NSPOTS][2 + NINSTR];
unsigned hotspotctr;

void
sigvtalrm(int s)
{
	unsigned pc = pc_start;

	(void)s;
	if (pc == 0)
		return;

	hotspots[hotspotctr % NSPOTS][0] = pc >> 8;
	hotspots[hotspotctr % NSPOTS][1] = pc & 0xff;
	memcpy(&hotspots[hotspotctr % NSPOTS][2], &memory[pc], NINSTR);

	hotspotctr++;
}

void
start_profile(void)
{
	struct itimerval itv = {{0}, {0}};
	int rc;

	itv.it_interval.tv_usec = 1000 /*1ms*/;
	itv.it_value.tv_usec = 1000 /*1ms*/;
	hotspotctr = 0;

	rc = setitimer(ITIMER_VIRTUAL, &itv, NULL);
	ASSERT(rc == 0, "setitimer");
}

void
stop_profile(void)
{
	struct itimerval itv = {{0}, {0}};
	int rc;

	rc = setitimer(ITIMER_VIRTUAL, &itv, NULL);
	ASSERT(rc == 0, "setitimer");
}

uint16_t
wordle(const void *p)
{
	const uint8_t *p8 = p;
	uint16_t res;

	res = p8[0] | ((uint16_t)p8[1] << 8);
	return res;
}

uint16_t
wordbe(const void *p)
{
	const uint8_t *p8 = p;
	uint16_t res;

	res = p8[1] | ((uint16_t)p8[0] << 8);
	return res;
}

int
cmp_spot(const void *a, const void *b)
{

	return memcmp(a, b, 2 + NINSTR);
	//return wordle(a) - wordle(b);
}

unsigned
count(unsigned start)
{
	unsigned res = 1, next = start;

	while (true) {
		next = (next + 1) % NSPOTS;
		if (memcmp(&hotspots[start][0], &hotspots[next][0], 2+NINSTR))
			break;
		res++;
	}
	return res;
}

void
analyze_hotspots(void)
{
	unsigned top = hotspotctr,
		 bottom;

	if (hotspotctr < NSPOTS)
		bottom = 0;
	else
		bottom = (hotspotctr + 1) % NSPOTS;

	printf("analysis start\n");
	qsort(hotspots, NSPOTS, 2 + NINSTR, cmp_spot);

	fprintf(profile, "Hotspots:\n");
	for (unsigned i = bottom; i != top;) {
		unsigned runlen = count(i);

		if (runlen > 8 && wordbe(&hotspots[i][0])) {
			fprintf(profile, "%d:", runlen);
			for (unsigned j = 0; j < runlen && j < 24; j += 8)
				putc('#', profile);
			fprintf(profile, ":@pc=%#04x instr:",
			    (uns)wordbe(&hotspots[i][0]));
			for (unsigned j = 0; j < NINSTR; j += 2)
				fprintf(profile, "%04x ",
				    (uns)wordle(&hotspots[i][2+j]));
			fprintf(profile, "\n");
		}

		i = (i + runlen) % NSPOTS;
	}
	fprintf(profile, "\n\n");
	fflush(profile);
	printf("analysis done\n");
}
#endif  // PROFILE_BFHW

int
main(int argc, char **argv)
{
	size_t rd, idx;
	FILE *romfile;
	uint64_t start;
	uintmax_t attempts = 0;

	if (getenv("BFHW_GENERATE"))
		attemptlimit = 45;

	(void)argc;
	(void)argv;

	romfile = fopen("roms/hollywood.bin", "rb");
	if (romfile == NULL) {
		printf("Couldn't find roms/hollywood.bin!\n");
		exit(1);
	}
	urandom = fopen("/dev/urandom", "rb");
	ASSERT(urandom, "fopen");

	idx = 0;
	while (true) {
		rd = fread(&rom[idx], 1, sizeof(rom) - idx, romfile);
		if (rd == 0)
			break;
		idx += rd;
	}
	// callgate
	rom[0x10] = 0x30;
	rom[0x11] = 0x41;

	fclose(romfile);
#if PROFILE_BFHW
	profile = fopen("profile.txt", "wb");
	ASSERT(profile, "io");

	signal(SIGVTALRM, sigvtalrm);
	start_profile();
#endif

	// Prime the fast-load rom/registers (Thanks, rmmh)
	fastrom = false;
	init();
	memcpy(memory, rom, sizeof memory);
	registers[PC] = memword(0xfffe);
	emulate();
	ASSERT(fastrom, "fastfastfast");

	start = now();
	while (true) {
		size_t rd;

		attempts++;

		insns = 0;
		init();

		//memcpy(memory, rom, sizeof memory);
		// Jump directly to getsn(). Do not pass go. Do not collect ...
		memcpy(memory, fastload, sizeof(memory));
		memcpy(registers, fastregisters, sizeof(registers));

		// generate new input
		rd = fread(attempt, 1, ATTEMPT_LEN, urandom);
		ASSERT(rd == ATTEMPT_LEN, "x");

#ifndef QUIET
		printf("Attempting: %02x%02x%02x%02x%02x\n", (uns)attempt[0],
		    (uns)attempt[1], (uns)attempt[2], (uns)attempt[3],
		    (uns)attempt[4]);
#endif

#if PROFILE_BFHW
		while (true) {
			emulate1();
			if (off)
				break;

			if (now() - start > 10*sec) {
				stop_profile();
				printf("%ju s elapsed -- ",
				    (uintmax_t)((now() - start) / sec));
				print_ips();
				start = now();
				insns = 0;
				analyze_hotspots();
				start_profile();
			}
		}
#else /* not profile */
		emulate();
#ifndef QUIET
		printf("Emulate: done (off: %d pc: 0x%04x insns: %jd)\n", off,
		    registers[PC], (uintmax_t)insns);
#endif // quiet
#endif // profile_bfhw

		if (unlocked) {
			printf("Success\n");
			printf("Solution: %02x%02x%02x%02x%02x\n",
			    (uns)attempt[0], (uns)attempt[1], (uns)attempt[2],
			    (uns)attempt[3], (uns)attempt[4]);
			break;
		}

		//memdiff(memory, rom);

		destroy();

		if (now() - start > 5*sec) {
			printf("%ju s elapsed -- attempt/s: %ju\n",
			    (uintmax_t)((now() - start) / sec),
			    (uintmax_t)((uintmax_t)attempts * sec / (now() - start)));
			attempts = 0;
			start = now();
		}

		if (attemptlimit && attempts >= attemptlimit)
			break;
	}

#if PROFILE_BFHW
	stop_profile();
#endif
	return 0;
}
