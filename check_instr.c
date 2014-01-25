#include "emu.h"

#include <check.h>

#define CODE_STEP   (0x4500)
#define CODE_REPEAT (0x4400)
#define PC_LOAD     (0xfffe)
#define CALL_GATE   (0x0010)

#define ck_assert_flags(flags) _ck_assert_flags(__LINE__, flags)

void
install_words_le(uint16_t *code, uint16_t addr, size_t sz)
{

	for (; sz > 1; sz -= 2) {
		uint16_t word = *code;

		memory[addr] = word & 0xff;
		memory[addr+1] = (word>>8) & 0xff;

		code++;
		addr += 2;
	}
}

void
setup_machine(void)
{
	uint16_t ret = 0x4130,
		 run = CODE_REPEAT;

	// zero regs/mem, clear symbols
	init();

	// Setup callgate (ret)
	install_words_le(&ret, CALL_GATE, sizeof(ret));

	// Setup initial PC value @4400 (full emulation)
	install_words_le(&run, PC_LOAD, sizeof(run));

	// Setup intitial PC for single-step emu
	registers[PC] = CODE_STEP;
}

void
teardown_machine(void)
{

	destroy();
}

static void
_ck_assert_flags(unsigned line, uint16_t exp)
{
	uint16_t actual = sr_flags();

	ck_assert_msg(actual == exp,
	    "l%u: expected flags: %#04x; actual: %#04x (diff: %#04x)", line,
	    exp, actual, exp ^ actual);
}

// mov #4400, sp
START_TEST(test_mov_const_reg)
{
	uint16_t code[] = {
		0x4031,
		0x4142,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[SP] == 0x4142);
}
END_TEST

// mov &#1000, r5
START_TEST(test_mov_sr_abs_reg)
{
	uint16_t code[] = {
		0x4215,
		0x1000,
	};
	uint16_t word = 0x1234;

	install_words_le(code, CODE_STEP, sizeof(code));
	install_words_le(&word, 0x1000, sizeof(word));

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0x1234);
}
END_TEST

// mov @r15+, #-0x1002(r15)
START_TEST(test_mov_pre_incr)
{
	uint16_t code[] = {
		0x4fbf,
		0xeffe,
	};
	uint16_t word = 0x1234;

	install_words_le(code, CODE_STEP, sizeof(code));
	install_words_le(&word, 0x2400, sizeof(word));
	registers[15] = 0x2400;

	emulate1();

	ck_assert(memword(0x1400) == word);
	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert_msg(registers[15] == 0x2402);
}
END_TEST

// mov	r5, &0x015c
START_TEST(test_mov_reg_abs)
{
	uint16_t code[] = {
		0x4582,
		0x015c,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0xbeef;

	emulate1();

	ck_assert(memword(0x015c) == 0xbeef);
	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert_msg(registers[5] == 0xbeef);
}
END_TEST

// and.b #-1, r5
START_TEST(test_and_b_cgneg1_reg)
{
	uint16_t code[] = { 0xf375, };

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0x8182;
	registers[SR] = 0xffef;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[5] == 0x0082);
	ck_assert_msg(sr_flags() == SR_C, "sr_flags: %#04x, not: %#04x",
	    sr_flags(), SR_C);
}
END_TEST

// and #-1, r5 (=-1)
START_TEST(test_and_flags1)
{
	uint16_t code[] = { 0xf335, };

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0xffff;
	registers[SR] = 0xffef;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[5] == 0xffff);
	ck_assert_msg(sr_flags() == (SR_C | SR_N), "sr_flags: %#04x", sr_flags());
}
END_TEST

// and #0x7fff, r5 (=-1)
START_TEST(test_and_flags2)
{
	uint16_t code[] = {
		0xf035,
		0x7fff,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0xffff;
	registers[SR] = 0xffef;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0x7fff);
	ck_assert_msg(sr_flags() == SR_C, "sr_flags: %#04x", sr_flags());
}
END_TEST

// and #0, r5 (=-1)
START_TEST(test_and_flags3)
{
	uint16_t code[] = { 0xf305, };

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0xffff;
	registers[SR] = 0xffef;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[5] == 0);
	ck_assert_msg(sr_flags() == SR_Z, "sr_flags: %#04x", sr_flags());
}
END_TEST

START_TEST(test_bis_imm_reg)
{
	uint16_t code[] = {
		// mov #0082, r5
		0x4035,
		0x0082,
		// bis #0x5a08, r5
		0xd035,
		0x5a08,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	emulate1();
	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 8);
	ck_assert(registers[5] == 0x5a8a);
}
END_TEST

START_TEST(test_bisb_imm_reg)
{
	uint16_t code[] = {
		// bis.b #0x5a08, r5
		0xd075,
		0x5a08,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0x8182;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0x008a);
}
END_TEST

START_TEST(test_cmp_const_reg)
{
	uint16_t code[] = {
		// tst r5   (aka: cmp #0, r5)
		0x9305,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[5] == 0);
	ck_assert_flags(SR_C | SR_Z);
}
END_TEST

START_TEST(test_cmp_imm_reg)
{
	uint16_t code[] = {
		// cmp #5, r5
		0x9035,
		0x0500,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0);
	ck_assert_flags(SR_N);
}
END_TEST

START_TEST(test_cmp_imm_mem)
{
	uint16_t code[] = {
		// cmp #5, @(r5)
		0x90b5,
		0x0005,
		0x0000,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0x2400;
	memwriteword(0x2400, 0x0100);

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 6);
	ck_assert(registers[5] == 0x2400);
	ck_assert_flags(SR_C);
}
END_TEST

START_TEST(test_cmpb_reg_reg)
{
	uint16_t code[] = {
		// cmp.b r4, r5
		0x9445,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[4] = 0xff;
	registers[5] = 0x2080;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[4] == 0xff);
	ck_assert(registers[5] == 0x2080);
	ck_assert_flags(0);
}
END_TEST

START_TEST(test_jmp_z)
{
	uint16_t code[] = {
		// jz $+0x10
		0x2407,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = 0;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
}
END_TEST

START_TEST(test_jmp_z2)
{
	uint16_t code[] = {
		// jz $+0x10
		0x2407,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = SR_Z;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 0x10);
}
END_TEST

START_TEST(test_jmp_nz)
{
	uint16_t code[] = {
		// jnz $-0x0a
		0x23fa,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = SR_Z;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
}
END_TEST

START_TEST(test_jmp_nz2)
{
	uint16_t code[] = {
		// jnz $-0x0a
		0x23fa,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = 0;

	emulate1();

	ck_assert_msg(registers[PC] == CODE_STEP - 0xa, "%04x != %04x",
	    (uns)registers[PC], CODE_STEP - 0xa);
}
END_TEST

START_TEST(test_jmp)
{
	uint16_t code[] = {
		// jmp $+0x10
		0x3c07,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 0x10);
}
END_TEST

START_TEST(test_jmp2)
{
	uint16_t code[] = {
		// jmp $-0xe
		0x3ff8,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	emulate1();

	ck_assert(registers[PC] == CODE_STEP - 0xe);
}
END_TEST

START_TEST(test_jmp_nc)
{
	uint16_t code[] = {
		// jnc $+0xe
		0x2806,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = SR_C;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
}
END_TEST

START_TEST(test_jmp_nc2)
{
	uint16_t code[] = {
		// jnc $+0xe
		0x2806,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = 0;

	emulate1();

	ck_assert_msg(registers[PC] == CODE_STEP + 0xe, "%04x != %04x",
	    (uns)registers[PC], CODE_STEP + 0xe);
}
END_TEST

START_TEST(test_jmp_c)
{
	uint16_t code[] = {
		// jc $+0xe
		0x2c06,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = 0;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
}
END_TEST

START_TEST(test_jmp_c2)
{
	uint16_t code[] = {
		// jc $+0xe
		0x2c06,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = SR_C;

	emulate1();

	ck_assert_msg(registers[PC] == CODE_STEP + 0xe, "%04x != %04x",
	    (uns)registers[PC], CODE_STEP + 0xe);
}
END_TEST

START_TEST(test_jmp_ge)
{
	uint16_t code[] = {
		// jge $+0x6
		0x3402,
	};

	uint16_t initflags[] = {
		0,
		SR_N,
		SR_V,
		SR_N|SR_V,
	};
	uint16_t offset[] = {
		6,
		2,
		2,
		6,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(initflags); i++) {
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + offset[i]);
		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_add_imm_reg)
{
	uint16_t code[] = {
		0x5035,		// add imm, r5
		0x1,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = 0xffef;
	registers[5] = 0xffff;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0);
	ck_assert_flags(SR_C | SR_Z);
	// arithmetic instructions clear upper byte of SR
	ck_assert(registers[SR] == 0x00eb);
}
END_TEST

START_TEST(test_addb_imm_reg)
{
	uint16_t code[] = {
		0x5075,		// add.b imm, r5
		0xbeef,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0xffff;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0xee);
	ck_assert_flags(SR_C);
}
END_TEST

START_TEST(test_addb_reg_reg)
{
	uint16_t code[] = {
		0x5445,		// add.b r4, r5
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[4] = 0x8010;
	registers[5] = 0x20f0;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[5] == 0);
	ck_assert_flags(SR_C | SR_Z);
}
END_TEST

START_TEST(test_addc)
{
	uint16_t code[] = {
		0x6405,		// addc r4, r5
	};

	uint16_t initial[] = {
		22588, 32074,
		26948, 54384,
		1753, 1196,
		14823, 30308,
		48520, 17015,
	};
	uint16_t initflags[] = {
		SR_C|SR_Z|SR_N,
		SR_Z|SR_N,
		SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
	};
	uint16_t result[] = {
		54663,
		15796,
		2949,
		45132,
		0,
	};
	uint16_t rflags[] = {
		SR_N,
		SR_C,
		0,
		SR_N,
		SR_C|SR_Z,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(result); i++) {
		registers[4] = initial[2*i];
		registers[5] = initial[2*i+1];
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + 2);
		ck_assert(registers[4] == initial[2*i]);
		ck_assert(registers[5] == result[i]);
		ck_assert_flags(rflags[i]);

		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_addcb)
{
	uint16_t code[] = {
		0x6445,		// addc.b r4, r5
	};

	uint16_t initial[] = {
		0x7f, 0x7f,
		0x80, 0x7f,
		0x01, 0x51,
	};
	uint16_t initflags[] = {
		SR_Z,
		SR_C|SR_N,
		SR_C|SR_N|SR_Z,
	};
	uint16_t result[] = {
		0xfe,
		0x00,
		0x53,
	};
	uint16_t rflags[] = {
		0,
		SR_Z|SR_C,
		0,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(result); i++) {
		registers[4] = initial[2*i];
		registers[5] = initial[2*i+1];
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + 2);
		ck_assert(registers[4] == initial[2*i]);
		ck_assert(registers[5] == result[i]);
		ck_assert_flags(rflags[i]);

		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_sub_const_reg)
{
	uint16_t code[] = {
		// dec r15   (aka: sub #1, r15)
		0x831f,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[15] = 0;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[15] == 0xffff);
	ck_assert_flags(SR_N);
}
END_TEST

START_TEST(test_sub_imm_reg)
{
	uint16_t code[] = {
		// sub #5, r5
		0x8035,
		0x5,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 10;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 5);
	ck_assert_flags(SR_C);

	registers[PC] = CODE_STEP;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0);
	ck_assert_flags(SR_Z | SR_C);
}
END_TEST

START_TEST(test_sub_imm_mem)
{
	uint16_t code[] = {
		// sub #5, 0x15(r5)
		0x80b5,
		0x0005,
		0x0015,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0x2401;
	memwriteword(0x2416, 0x0100);

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 6);
	ck_assert(registers[5] == 0x2401);
	ck_assert_flags(SR_C);
	ck_assert(memword(0x2416) == 0x00fb);
}
END_TEST

START_TEST(test_subb_reg_reg)
{
	uint16_t code[] = {
		// sub.b r4, r5
		0x8445,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[4] = 0x0025;
	registers[5] = 0xf00f;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[5] == 0x00ea);
	ck_assert(registers[4] == 0x0025);
	ck_assert_flags(0);
}
END_TEST

START_TEST(test_subb_reg_reg2)
{
	uint16_t code[] = {
		// sub.b r4, r5
		0x8445,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[4] = 0xf;
	registers[5] = 0xf00f;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[5] == 0);
	ck_assert(registers[4] == 0xf);
	ck_assert_flags(SR_C | SR_Z);
}
END_TEST

START_TEST(test_call_sp)
{
	uint16_t code[] = {
		// call sp
		0x1281,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SP] = 0x4000;

	emulate1();

	ck_assert(registers[PC] == 0x4000);
	ck_assert(registers[SP] == 0x3ffe);
	ck_assert(memword(0x3ffe) == CODE_STEP + 2);
}
END_TEST

START_TEST(test_call_imm)
{
	uint16_t code[] = {
		// call imm
		0x12b0,
		0x1234,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SP] = 0x4000;

	emulate1();

	ck_assert(registers[PC] == 0x1234);
	ck_assert(registers[SP] == 0x3ffe);
	ck_assert(memword(0x3ffe) == CODE_STEP + 4);
}
END_TEST

START_TEST(test_push_reg)
{
	uint16_t code[] = {
		// push r11
		0x120b,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SP] = 0x4000;
	registers[11] = 0xdead;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[SP] == 0x3ffe);
	ck_assert(memword(0x3ffe) == 0xdead);
}
END_TEST

START_TEST(test_push_imm)
{
	uint16_t code[] = {
		// push #0xbeef
		0x1230,
		0xbeef,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SP] = 0x4000;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[SP] == 0x3ffe);
	ck_assert(memword(0x3ffe) == 0xbeef);
}
END_TEST

START_TEST(test_push_sp_incr)
{
	uint16_t code[] = {
		// push @sp+
		0x1231,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SP] = 0x4000;
	memwriteword(0x3ffe, 0xa1b1);
	memwriteword(0x4000, 0xc1d1);
	memwriteword(0x4002, 0xe1f1);

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[SP] == 0x4000);
	ck_assert(memword(0x3ffe) == 0xa1b1);
	ck_assert(memword(0x4000) == 0xc1d1);
	ck_assert(memword(0x4002) == 0xe1f1);
}
END_TEST

START_TEST(test_sxt_reg)
{
	uint16_t code[] = {
		0x118f,		// sxt r15
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[15] = 0x80;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[15] == 0xff80);
	ck_assert_flags(SR_C | SR_N);
}
END_TEST

START_TEST(test_sxt_reg2)
{
	uint16_t code[] = {
		0x118f,		// sxt r15
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[15] = 0x7f;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[15] == 0x007f);
	ck_assert_flags(SR_C);
}
END_TEST

START_TEST(test_sxt_reg3)
{
	uint16_t code[] = {
		0x118f,		// sxt r15
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[15] = 0;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[15] == 0);
	ck_assert_flags(SR_Z);
}
END_TEST

START_TEST(test_swpb_r15)
{
	uint16_t code[] = {
		0x108f,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[15] = 0xbeef;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[15] == 0xefbe);
	ck_assert_flags(0);
}
END_TEST

START_TEST(test_xor)
{
	uint16_t code[] = {
		0xe405,		// xor r4, r5
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[4] = 0xffff;
	registers[5] = 0xbeef;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[4] == 0xffff);
	ck_assert(registers[5] == 0x4110);
	ck_assert_flags(SR_C);
}
END_TEST

START_TEST(test_nop)
{
	uint16_t code[] = {
		0x4303,		// mov cg, cg
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
}
END_TEST

START_TEST(test_rrc)
{
	uint16_t code[] = {
		0x100e,		// rrc r14
	};

	uint16_t initial[] = {
		0x1,
		0x0,
		0xa5a5,
		0x52d2,
	};
	uint16_t initflags[] = {
		0x0,
		SR_C | SR_Z,
		0x0,
		SR_C,
	};
	uint16_t result[] = {
		0x0,
		0x8000,
		0x52d2,
		0xa969,
	};
	uint16_t rflags[] = {
		SR_C,
		SR_N,
		SR_C,
		SR_N,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(initial); i++) {
		registers[14] = initial[i];
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + 2);
		ck_assert(registers[14] == result[i]);
		ck_assert_flags(rflags[i]);

		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_rrcb)
{
	uint16_t code[] = {
		0x104e,		// rrc.b r14
	};

	uint16_t initial[] = {
		0x1,
		0x0,
		0xa5a5,
		0x52d2,
	};
	uint16_t initflags[] = {
		0,
		SR_C | SR_Z,
		SR_Z,
		SR_C | SR_Z,
	};
	uint16_t result[] = {
		0x0,
		0x80,
		0x52,
		0xe9,
	};
	uint16_t rflags[] = {
		SR_C,
		0,
		SR_C,
		0,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(initial); i++) {
		registers[14] = initial[i];
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + 2);
		ck_assert(registers[14] == result[i]);
		ck_assert_flags(rflags[i]);

		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_dadd)
{
	uint16_t code[] = {
		0xa405,		// dadd r4, r5
	};

	uint16_t initial[] = {
		0x160e, 0x04a2,
		0x0845, 0x3c01,
		0x3c01, 0x0f51,
		0xf, 0xf,
		0xb000, 0x0185,
	};
	uint16_t initflags[] = {
		SR_C|SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
		SR_C|SR_Z,
	};
	uint16_t result[] = {
		0x2116,
		0x4a46,
		0x4152,
		0x0014,
		0x1185,
	};
	uint16_t rflags[] = {
		SR_Z|SR_N,
		SR_Z|SR_N,
		SR_Z|SR_N,
		SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(result); i++) {
		registers[4] = initial[2*i];
		registers[5] = initial[2*i+1];
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + 2);
		ck_assert(registers[4] == initial[2*i]);
		ck_assert(registers[5] == result[i]);
		ck_assert_flags(rflags[i]);

		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_daddb)
{
	uint16_t code[] = {
		0xa445,		// dadd.b r4, r5
	};

	uint16_t initial[] = {
		0x0e, 0xa2,
		0x45, 0x01,
		0x01, 0x51,
		0x0f, 0x0f,
		0xb0, 0x05,
	};
	uint16_t initflags[] = {
		SR_C|SR_Z,
		SR_C|SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
		SR_C|SR_Z,
	};
	uint16_t result[] = {
		0x16,
		0x46,
		0x52,
		0x14,
		0x15,
	};
	uint16_t rflags[] = {
		SR_C|SR_Z|SR_N,
		SR_Z|SR_N,
		SR_Z|SR_N,
		SR_Z|SR_N,
		SR_C|SR_Z|SR_N,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(result); i++) {
		registers[4] = initial[2*i];
		registers[5] = initial[2*i+1];
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + 2);
		ck_assert(registers[4] == initial[2*i]);
		ck_assert(registers[5] == result[i]);
		ck_assert_flags(rflags[i]);

		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_dadd_pcind_reg)
{
	uint16_t code[] = {
		0xa02e,		// dadd @pc, r14
		0x3c01,		// another instruction
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[14] = 0;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 2);
	ck_assert(registers[14] == 0x4201);
	ck_assert_flags(0);
}
END_TEST

START_TEST(test_rra)
{
	uint16_t code[] = {
		0x1105,		// rra r5
	};

	uint16_t initial[] = {
		0xff80,
		0x0001,
		0x8000,
	};
	uint16_t initflags[] = {
		SR_C|SR_Z,
		SR_Z|SR_N,
		SR_C|SR_Z,
	};
	uint16_t result[] = {
		0xffc0,
		0x0000,
		0xc000,
	};
	uint16_t rflags[] = {
		SR_C|SR_N,
		SR_N,
		SR_C|SR_N,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(initial); i++) {
		registers[5] = initial[i];
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + 2);
		ck_assert(registers[5] == result[i]);
		ck_assert_flags(rflags[i]);

		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_rrab)
{
	uint16_t code[] = {
		0x1145,		// rra.b r5
	};

	uint16_t initial[] = {
		0xff80,
		0x0001,
		0x8080,
	};
	uint16_t initflags[] = {
		SR_C|SR_Z,
		SR_Z|SR_N,
		SR_C|SR_Z,
	};
	uint16_t result[] = {
		0xc0,
		0x00,
		0xc0,
	};
	uint16_t rflags[] = {
		SR_C,
		SR_N,
		SR_C,
	};

	install_words_le(code, CODE_STEP, sizeof(code));

	for (unsigned i = 0; i < ARRAYLEN(initial); i++) {
		registers[5] = initial[i];
		registers[SR] = initflags[i];

		emulate1();

		ck_assert(registers[PC] == CODE_STEP + 2);
		ck_assert(registers[5] == result[i]);
		ck_assert_flags(rflags[i]);

		registers[PC] = CODE_STEP;
	}
}
END_TEST

START_TEST(test_adc_indpc)
{
	uint16_t code[] = {
		0x6380,		// addc #0, 2(pc)
		0x0002,
		0x4444,
		0x6666,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[SR] = SR_C;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(memword(CODE_STEP + 2) == 0x2);
	ck_assert(memword(CODE_STEP + 4) == 0x4444);
	ck_assert(memword(CODE_STEP + 6) == 0x6667);
	ck_assert_flags(0);
}
END_TEST

START_TEST(test_symbolic)
{
	uint16_t code[] = {
		0x5035,		// add imm, r5
		0x1337,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	register_symbols[5] = mkinp(0);

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(isregsym(SR));
	ck_assert(isregsym(5));
	ck_assert(regsym(5)->s_kind == S_PLUS);
	//ck_assert_str_eq("(0x1337) + (X)", regsym(5)->symbolic);
	//ck_assert_str_eq("sr((0x1337) + (X))", regsym(SR)->symbolic);
}
END_TEST

START_TEST(test_symbolicb)
{
	uint16_t code[] = {
		0x5075,		// add.b imm, r5
		0x1337,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	register_symbols[5] = mkinp(0);

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(isregsym(SR));
	ck_assert(isregsym(5));
	ck_assert(regsym(5)->s_kind == S_AND);
	//ck_assert_str_eq("(((0x37) & 0xff) + ((X) & 0xff)) & 0xff",
	//    regsym(5)->symbolic);
	//ck_assert_str_eq("sr((((0x37) & 0xff) + ((X) & 0xff)) & 0xff)",
	//    regsym(SR)->symbolic);
}
END_TEST

START_TEST(test_peephole)
{
	struct sexp *test =
	    mksexp(S_XOR, 2,
		mksexp(S_XOR, 2,
		    mkinp(0),
		    mkinp(1)),
		mkinp(2));
	struct sexp *res;

	//printsym(test);
	res = peephole(test);
	//printsym(res);

	ck_assert(res->s_kind == S_XOR);
	ck_assert(res->s_nargs == 3);
	ck_assert(res->s_arg[0]->s_kind == S_INP);
	ck_assert(res->s_arg[0]->s_nargs == 2);
	ck_assert(res->s_arg[1]->s_kind == S_INP);
	ck_assert(res->s_arg[1]->s_nargs == 0);
	ck_assert(res->s_arg[2]->s_kind == S_INP);
	ck_assert(res->s_arg[2]->s_nargs == 1);
}
END_TEST

START_TEST(test_peephole2)
{
	struct sexp *test =
	    mksexp(S_XOR, 3, mkinp(0), mkinp(1), mkinp(0));
	struct sexp *res;

	//printsym(test);
	res = peephole(test);
	//printsym(res);

	ck_assert(res->s_kind == S_INP);
	ck_assert(res->s_nargs == 1);
}
END_TEST

START_TEST(test_peephole3)
{
	struct sexp *test =
	    mksexp(S_LSHIFT, 2,
		mksexp(S_RSHIFT, 2,
		    mksexp(S_LSHIFT, 2,
			mkinp(0),
			sexp_imm_alloc(8)),
		    sexp_imm_alloc(12)),
		sexp_imm_alloc(12));
	struct sexp *res;

	//printsym(test);
	res = peephole(test);
	//printsym(res);

	ck_assert(res->s_kind == S_AND);
	ck_assert(res->s_nargs == 2);
	ck_assert(res->s_arg[0] == test->s_arg[0]->s_arg[0]);
	ck_assert(res->s_arg[1]->s_kind == S_IMMEDIATE);
	ck_assert(res->s_arg[1]->s_nargs == 0xf000);
}
END_TEST

START_TEST(test_peephole4)
{
	struct sexp *test =
	    mksexp(S_XOR, 3, mkinp(0), mkinp(1), mkinp(2));
	struct sexp *res;
	uint16_t code[] = {
		// push r5
		0x1205,
		// pop r5
		0x4135,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	register_symbols[5] = test;
	//printsym(test);

	emulate1();
	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(isregsym(5));

	res = register_symbols[5];
	//printsym(res);

	ck_assert(res->s_kind == S_XOR);
	ck_assert(res->s_nargs == 3);
	ck_assert(res == test);
}
END_TEST

Suite *
suite_instr(void)
{
	Suite *s = suite_create("instr");

	TCase *tmov = tcase_create("mov");
	tcase_add_checked_fixture(tmov, setup_machine, teardown_machine);
	tcase_add_test(tmov, test_mov_const_reg);
	tcase_add_test(tmov, test_mov_sr_abs_reg);
	tcase_add_test(tmov, test_mov_pre_incr);
	tcase_add_test(tmov, test_mov_reg_abs);
	suite_add_tcase(s, tmov);

	TCase *tand = tcase_create("and");
	tcase_add_checked_fixture(tand, setup_machine, teardown_machine);
	tcase_add_test(tand, test_and_b_cgneg1_reg);
	tcase_add_test(tand, test_and_flags1);
	tcase_add_test(tand, test_and_flags2);
	tcase_add_test(tand, test_and_flags3);
	suite_add_tcase(s, tand);

	TCase *tbis = tcase_create("bis");
	tcase_add_checked_fixture(tbis, setup_machine, teardown_machine);
	tcase_add_test(tbis, test_bis_imm_reg);
	tcase_add_test(tbis, test_bisb_imm_reg);
	suite_add_tcase(s, tbis);

	TCase *tcmp = tcase_create("cmp");
	tcase_add_checked_fixture(tcmp, setup_machine, teardown_machine);
	tcase_add_test(tcmp, test_cmp_const_reg);
	tcase_add_test(tcmp, test_cmp_imm_reg);
	tcase_add_test(tcmp, test_cmp_imm_mem);
	tcase_add_test(tcmp, test_cmpb_reg_reg);
	suite_add_tcase(s, tcmp);

	TCase *tjmp = tcase_create("jmp");
	tcase_add_checked_fixture(tjmp, setup_machine, teardown_machine);
	tcase_add_test(tjmp, test_jmp_z);
	tcase_add_test(tjmp, test_jmp_z2);
	tcase_add_test(tjmp, test_jmp_nz);
	tcase_add_test(tjmp, test_jmp_nz2);
	tcase_add_test(tjmp, test_jmp);
	tcase_add_test(tjmp, test_jmp2);
	tcase_add_test(tjmp, test_jmp_nc);
	tcase_add_test(tjmp, test_jmp_nc2);
	tcase_add_test(tjmp, test_jmp_c);
	tcase_add_test(tjmp, test_jmp_c2);
	tcase_add_test(tjmp, test_jmp_ge);
	suite_add_tcase(s, tjmp);

	TCase *tsub = tcase_create("sub");
	tcase_add_checked_fixture(tsub, setup_machine, teardown_machine);
	tcase_add_test(tsub, test_sub_const_reg);
	tcase_add_test(tsub, test_sub_imm_reg);
	tcase_add_test(tsub, test_sub_imm_mem);
	tcase_add_test(tsub, test_subb_reg_reg);
	tcase_add_test(tsub, test_subb_reg_reg2);
	suite_add_tcase(s, tsub);

	TCase *tadd = tcase_create("add");
	tcase_add_checked_fixture(tadd, setup_machine, teardown_machine);
	tcase_add_test(tadd, test_add_imm_reg);
	tcase_add_test(tadd, test_addb_imm_reg);
	tcase_add_test(tadd, test_addb_reg_reg);
	tcase_add_test(tadd, test_addc);
	tcase_add_test(tadd, test_addcb);
	tcase_add_test(tadd, test_adc_indpc);
	suite_add_tcase(s, tadd);

	TCase *tcall = tcase_create("call");
	tcase_add_checked_fixture(tcall, setup_machine, teardown_machine);
	tcase_add_test(tcall, test_call_sp);
	tcase_add_test(tcall, test_call_imm);
	suite_add_tcase(s, tcall);

	TCase *tpush = tcase_create("push");
	tcase_add_checked_fixture(tpush, setup_machine, teardown_machine);
	tcase_add_test(tpush, test_push_reg);
	tcase_add_test(tpush, test_push_imm);
	tcase_add_test(tpush, test_push_sp_incr);
	suite_add_tcase(s, tpush);

	TCase *tsxt = tcase_create("sxt");
	tcase_add_checked_fixture(tsxt, setup_machine, teardown_machine);
	tcase_add_test(tsxt, test_sxt_reg);
	tcase_add_test(tsxt, test_sxt_reg2);
	tcase_add_test(tsxt, test_sxt_reg3);
	suite_add_tcase(s, tsxt);

	TCase *tswpb = tcase_create("swpb");
	tcase_add_checked_fixture(tswpb, setup_machine, teardown_machine);
	tcase_add_test(tswpb, test_swpb_r15);
	suite_add_tcase(s, tswpb);

	TCase *txor = tcase_create("xor");
	tcase_add_checked_fixture(txor, setup_machine, teardown_machine);
	tcase_add_test(txor, test_xor);
	suite_add_tcase(s, txor);

	TCase *tnop = tcase_create("nop");
	tcase_add_checked_fixture(tnop, setup_machine, teardown_machine);
	tcase_add_test(tnop, test_nop);
	suite_add_tcase(s, tnop);

	TCase *trrc = tcase_create("rrc");
	tcase_add_checked_fixture(trrc, setup_machine, teardown_machine);
	tcase_add_test(trrc, test_rrc);
	tcase_add_test(trrc, test_rrcb);
	suite_add_tcase(s, trrc);

	TCase *tdadd = tcase_create("dadd");
	tcase_add_checked_fixture(tdadd, setup_machine, teardown_machine);
	tcase_add_test(tdadd, test_dadd);
	tcase_add_test(tdadd, test_daddb);
	tcase_add_test(tdadd, test_dadd_pcind_reg);
	suite_add_tcase(s, tdadd);

	TCase *trra = tcase_create("rra");
	tcase_add_checked_fixture(trra, setup_machine, teardown_machine);
	tcase_add_test(trra, test_rra);
	tcase_add_test(trra, test_rrab);
	suite_add_tcase(s, trra);

	TCase *tsymbolic = tcase_create("symbolic");
	tcase_add_checked_fixture(tsymbolic, setup_machine, teardown_machine);
	tcase_add_test(tsymbolic, test_symbolic);
	tcase_add_test(tsymbolic, test_symbolicb);
	tcase_add_test(tsymbolic, test_peephole);
	tcase_add_test(tsymbolic, test_peephole2);
	tcase_add_test(tsymbolic, test_peephole3);
	tcase_add_test(tsymbolic, test_peephole4);
	suite_add_tcase(s, tsymbolic);

	return s;
}

int
main(void)
{
	Suite *s = suite_instr();
	SRunner *sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	return srunner_ntests_failed(sr);
}
