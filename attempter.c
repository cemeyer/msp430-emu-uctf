#include "emu.h"

static void
andflags_sr(unsigned res, uint16_t *sr)
{

	*sr &= ~(SR_V | 0xfe00);

	if (res & 0x8000)
		*sr |= SR_N;
	else
		*sr &= ~SR_N;
	if (res == 0) {
		*sr |= SR_Z;
		*sr &= ~SR_C;
	} else {
		*sr &= ~SR_Z;
		*sr |= SR_C;
	}
}

static void
addflags_sr(unsigned res, unsigned bw, uint16_t *sr)
{
	unsigned sz = 16;

	if (bw)
		sz = 8;

	if (bw == 0 && (res & 0x8000))
		*sr |= SR_N;
	else
		*sr &= ~SR_N;

	// #uctf never sets V. Only clear on arithmetic, though.
	*sr &= ~SR_V;
	*sr &= ~0xfe00;
#if 0
	if ((res & 0x8000) ^ (orig & 0x8000))
		*set |= SR_V;
#endif

	if ((res & ((1 << sz) - 1)) == 0)
		*sr |= SR_Z;
	else
		*sr &= ~SR_Z;

	if (res & (1 << sz))
		*sr |= SR_C;
	else
		*sr &= ~SR_C;
}

#include "trace_c.c"

void
inputs(unsigned idx, unsigned depthrem)
{

	if (depthrem == 0) {
		try();

		if (unlocked) {
			printf("Solved!\n");
			exit(0);
		}
		return;
	}

	for (unsigned i = 0; i < 256; i++) {
		Input[idx] = i;
		inputs(idx + 1, depthrem - 1);
	}
}

int
main(void)
{

	for (unsigned i = 1; i < 7; i++) {
		printf("Trying input len: %d\n", i);
		InputLen = i;
		inputs(0, i);
	}

	return 0;
}
