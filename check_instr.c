#include "emu.h"

#include <check.h>

#define CODE_STEP   (0x4500)
#define CODE_REPEAT (0x4400)
#define PC_LOAD     (0xfffe)
#define CALL_GATE   (0x0010)

#define ck_assert_taints(reg, args...) \
    _ck_assert_taints(reg, args, 0x10000)

#define ck_assert_taint_mem(addr, args...) \
    _ck_assert_taint_mem(addr, args, 0x10000)

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

	// zero regs/mem, clear taints
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

void
_ck_assert_taints(uint16_t reg, ...)
{
	struct taint *rt = register_taint[reg];
	char staints[600],
	     rtaints[600];
	unsigned n = 0, addr;
	va_list ap;

	strcpy(staints, "<");
	strcpy(rtaints, "<");

	for (unsigned i = 0; i < rt->ntaints; i++)
		sprintf(&staints[strlen(staints)], "%#04x,", rt->addrs[i]);
	strcat(staints, ">");

	va_start(ap, reg);
	while ((addr = va_arg(ap, unsigned)) != 0x10000) {
		bool found = false;

		sprintf(&rtaints[strlen(rtaints)], "%#04x,", addr);

		for (unsigned i = 0; i < rt->ntaints; i++) {
			if (rt->addrs[i] == addr) {
				found = true;
				break;
			}
		}
		if (!found)
			ck_abort_msg("r%d: %#04x not found (taints: %s)\n",
			    reg, addr, staints);
		n++;
	}
	va_end(ap);

	strcat(rtaints, ">");

	if (n != rt->ntaints)
		ck_abort_msg("r%d: More tainted than expected. Exp: %s, Act:"
		    " %s.\n", reg, rtaints, staints);
}

void
_ck_assert_taint_mem(uint16_t daddr, ...)
{
	struct taint *mt;
	char staints[600],
	     rtaints[600];
	unsigned n = 0, addr;
	va_list ap;

	mt = g_hash_table_lookup(memory_taint, GINT_TO_POINTER(daddr));

	strcpy(staints, "<");
	strcpy(rtaints, "<");

	for (unsigned i = 0; mt && i < mt->ntaints; i++)
		sprintf(&staints[strlen(staints)], "%#04x,", mt->addrs[i]);
	strcat(staints, ">");

	va_start(ap, daddr);
	while ((addr = va_arg(ap, unsigned)) != 0x10000) {
		bool found = false;

		sprintf(&rtaints[strlen(rtaints)], "%#04x,", addr);

		for (unsigned i = 0; mt && i < mt->ntaints; i++) {
			if (mt->addrs[i] == addr) {
				found = true;
				break;
			}
		}
		if (!found)
			ck_abort_msg("%#04x: %#04x not found (taints: %s)\n",
			    daddr, addr, staints);
		n++;
	}
	va_end(ap);

	strcat(rtaints, ">");

	if (mt && n != mt->ntaints)
		ck_abort_msg("%#04x: More tainted than expected. Exp: %s,"
		    " Act: %s.\n", daddr, rtaints, staints);
}

// mov #4400, sp
START_TEST(test_mov_const_reg)
{
	uint16_t code[] = {
		0x4031,
		0x4142,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	taint_mem(CODE_STEP + 2);

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[SP] == 0x4142);
	ck_assert(regtaintedexcl(SP, CODE_STEP + 2));
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
	taint_mem(0x1000);

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0x1234);
	ck_assert(regtaintedexcl(5, 0x1000));
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
	taint_mem(0x2400);
	registers[15] = 0x2400;

	emulate1();

	ck_assert(memword(0x1400) == word);
	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert_msg(registers[15] == 0x2402);
	ck_assert_taint_mem(0x1400, 0x2400);
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
	taint_mem(CODE_STEP + 2);
	registers[5] = 0xffff;
	registers[SR] = 0xffef;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0x7fff);
	ck_assert_msg(sr_flags() == SR_C, "sr_flags: %#04x", sr_flags());
	ck_assert_taints(5, CODE_STEP + 2);
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
	taint_mem(CODE_STEP + 2);
	taint_mem(CODE_STEP + 6);

	emulate1();
	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 8);
	ck_assert(registers[5] == 0x5a8a);
	ck_assert(regtainted(5, CODE_STEP + 2));
	ck_assert(regtainted(5, CODE_STEP + 6));
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
	taint_mem(CODE_STEP + 2);
	registers[5] = 0x8182;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0x008a);
	ck_assert(regtaintedexcl(5, CODE_STEP + 2));
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
	ck_assert_msg(sr_flags() == SR_Z, "sr_flags: %#04x", sr_flags());
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
	ck_assert_msg(sr_flags() == (SR_N | SR_C), "sr_flags: %#04x",
	    sr_flags());
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
	ck_assert_msg(sr_flags() == 0, "sr_flags: %#04x", sr_flags());
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
	ck_assert_msg(sr_flags() == (SR_C | SR_N), "sr_flags: %#04x",
	    sr_flags());
}
END_TEST

START_TEST(test_add_imm_reg)
{
	uint16_t code[] = {
		0x5035,		// add imm, r5
		0x1,
	};

	install_words_le(code, CODE_STEP, sizeof(code));
	registers[5] = 0xffff;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0);
	ck_assert_msg(sr_flags() == (SR_C | SR_Z), "sr_flags: %#04x",
	    sr_flags());
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
	ck_assert_msg(sr_flags() == 0, "sr_flags: %#04x",
	    sr_flags());

	registers[PC] = CODE_STEP;

	emulate1();

	ck_assert(registers[PC] == CODE_STEP + 4);
	ck_assert(registers[5] == 0);
	ck_assert_msg(sr_flags() == SR_Z, "sr_flags: %#04x", sr_flags());
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
	ck_assert_msg(sr_flags() == 0, "sr_flags: %#04x", sr_flags());
	ck_assert(memword(0x2416) == 0x00fb);
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
	suite_add_tcase(s, tcmp);

	TCase *tjmp = tcase_create("jmp");
	tcase_add_checked_fixture(tjmp, setup_machine, teardown_machine);
	tcase_add_test(tjmp, test_jmp_z);
	tcase_add_test(tjmp, test_jmp_z2);
	tcase_add_test(tjmp, test_jmp_nz);
	tcase_add_test(tjmp, test_jmp_nz2);
	suite_add_tcase(s, tjmp);

	TCase *tsub = tcase_create("sub");
	tcase_add_checked_fixture(tsub, setup_machine, teardown_machine);
	tcase_add_test(tsub, test_sub_const_reg);
	tcase_add_test(tsub, test_sub_imm_reg);
	tcase_add_test(tsub, test_sub_imm_mem);
	suite_add_tcase(s, tsub);

	TCase *tadd = tcase_create("add");
	tcase_add_checked_fixture(tadd, setup_machine, teardown_machine);
	tcase_add_test(tadd, test_add_imm_reg);
	suite_add_tcase(s, tadd);

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
