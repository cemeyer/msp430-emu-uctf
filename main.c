#include "emu.h"

uint16_t	 pc_start;
uint16_t	 registers[16];
uint8_t		 memory[0x10000];
struct taint	*register_taint[16];
GHashTable	*memory_taint;		// addr -> struct taint

void
init(void)
{

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
		rd = fread(memory, 1, sizeof(memory) - idx, romfile);
		if (rd == 0)
			break;
		idx += rd;
	}
	printf("Loaded %zu words from image.\n", idx);

	fclose(romfile);

	// XXX set memory taints
	// XXX or just auto-set on getsn()

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
	unsigned res = 0x10000;
	uint16_t setflags = 0,
		 clrflags = SR_V /* per #uctf emu */;

	inc_reg(PC, 0);

	//printf("Src,Ad,bw,As,Dst\n%#04x,%#02x,%#02x,%#02x,%#04x\n", (uns)dsrc,
	//    (uns)Ad, (uns)bw, (uns)As, (uns)ddst);
	load_src(instr, dsrc, As, bw, &srcval, &srckind);
	load_dst(instr, ddst, Ad, &dstval, &dstkind);

	switch (bits(instr, 15, 12)) {
	case 0x4000:
		// MOV (no flags)
		//printf("DDD MOV(src:%x, dst: %x, as:%x, ad:%x, b/w:%x)\n",
		//    (uns)dsrc, (uns)ddst, (uns)As, (uns)Ad, (uns)bw);

		if (dstkind == OP_REG) {
			if (srckind == OP_MEM) {
				printf("DDD MOV @%#04x (%#04x), r%d\n",
				    (uns)srcval, (uns)memword(srcval),
				    (uns)dstval);
				res = memword(srcval);
				copytaint(&register_taint[dstval],
				    g_hash_table_lookup(memory_taint,
					GINT_TO_POINTER(srcval)));
			} else
				unhandled(instr);
		} else if (dstkind == OP_MEM) {
			if (bw) {
			} else {
				ASSERT((dstval & 0x1) == 0, "word store "
				    "unaligned: %#04x", (unsigned)dstval);
			}

			unhandled(instr);
		} else
			unhandled(instr);

		break;
	case 0xd000:
		// BIS (no flags)
		if (dstkind == OP_REG) {
			if (srckind == OP_MEM) {
				printf("DDD BIS @%#04x (%#04x), r%d\n",
				    (uns)srcval, (uns)memword(srcval),
				    (uns)dstval);
				addtaint(&register_taint[dstval],
				    g_hash_table_lookup(memory_taint,
					GINT_TO_POINTER(srcval)));

				res = (registers[dstval] | memword(srcval));
			} else
				unhandled(instr);
		} else
			unhandled(instr);
		break;
	case 0xf000:
		// AND
		if (dstkind == OP_REG) {
			if (srckind == OP_CONST) {
				printf("DDD AND #%#04x, r%d\n", (uns)srcval,
				    (uns)dstval);

				res = registers[dstval] & srcval;
			} else if (srckind == OP_MEM) {
				printf("DDD AND @#%#04x (%#04x), r%d\n",
				    (uns)srcval, (uns)memword(srcval),
				    (uns)dstval);

				addtaint(&register_taint[dstval],
				    g_hash_table_lookup(memory_taint,
					GINT_TO_POINTER(srcval)));
				res = registers[dstval] & memword(srcval);
			} else {
				ASSERT(srckind == OP_REG, "enum invalid");
				unhandled(instr);
			}

			if (bw)
				res &= 0x00ff;

			if (res & 0x8000)
				setflags |= SR_N;
			else
				clrflags |= SR_N;
			if (res == 0) {
				setflags |= SR_Z;
				clrflags |= SR_C;
			} else {
				clrflags |= SR_Z;
				setflags |= SR_C;
			}
		} else
			unhandled(instr);
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

	if (instr_decode_src == PC) {
		if (As == AS_REGIND)
			illins(instr);
	}

	switch (instr_decode_src) {
	case SR:
		switch (As) {
		case AS_R2_ABS:
			extensionword = memword(registers[PC]);
			inc_reg(PC, 0);

			*srckind = OP_MEM;
			*srcval = extensionword;
			break;
		default:
			unhandled(instr);
			break;
		}
		break;
	case CG:
		switch (As) {
		case AS_R3_0:
			*srckind = OP_CONST;
			*srcval = 0;
			break;
		case AS_R3_NEG:
			*srckind = OP_CONST;
			*srcval = 0xffff;
			break;
		default:
			unhandled(instr);
			break;
		}
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
unhandled(uint16_t instr)
{

	printf("Instruction: %#04x @PC=%#04x is not implemented\n",
	    (unsigned)instr, (unsigned)pc_start);
	printf("Raw at PC: ");
	for (unsigned i = 0; i < 6; i++)
		printf("%02x", memory[pc_start+i]);
	printf("\n");
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

uint16_t
sr_flags(void)
{

	return registers[SR] & (SR_V | SR_CPUOFF | SR_N | SR_Z | SR_C);
}
