#ifndef EMU_H
#define EMU_H

#define _GNU_SOURCE

#include <sys/cdefs.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#define likely(cond) __builtin_expect ((cond), 1)
#define unlikely(cond) __builtin_expect ((cond), 0)

#define ARRAYLEN(arr) ((sizeof(arr)) / sizeof((arr)[0]))

#define min(x, y)  ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#if SYMBOLIC
enum sexp_kind {
	S_OR,
	S_XOR,
	S_AND,
	S_PLUS,
	S_IMMEDIATE,	// s_nargs -> value
	S_SR,
	S_EQ,
	S_SR_AND,
	S_SR_RRC,
	S_SR_RRA,
	S_RSHIFT,
	S_LSHIFT,
	S_RRA,
	S_INP,		// s_nargs -> index
	S_MATCH_ANY,
	S_SXT,

	S_SUBSEXP_MATCH,
};

#define SUBSEXP_MATCH_EXP 0xbeef
#define SUBSEXP_MATCH_IMM 0xcafe
#define SEXP_MAXARGS 4
struct sexp {
	enum sexp_kind	 s_kind;
	unsigned	 s_nargs;
	struct sexp	*s_arg[SEXP_MAXARGS];
};
#endif

extern uint16_t		 pc_start;
extern uint8_t		 pageprot[0x100];
extern uint16_t		 registers[16];
extern uint8_t		 memory[0x10000];
extern struct sexp	*register_symbols[16];
extern GHashTable	*memory_symbols;		// addr -> struct sexp*
extern bool		 off;
extern bool		 unlocked;
extern bool		 dep_enabled;
extern bool		 replay_mode;
extern bool		 stepone;
extern uint64_t		 insns;
extern uint64_t		 insnreplaylim;
extern uint64_t		 insnlimit;

#define DEP_R 0x4
#define DEP_W 0x2
#define DEP_X 0x1

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

#define SR_V      0x0100
#define SR_CPUOFF 0x0010
#define SR_N      0x0004
#define SR_Z      0x0002
#define SR_C      0x0001

#define sec       1000000ULL
#define ptr(X)    ((void*)((uintptr_t)X))

enum operand_kind {
	OP_REG,		// reg direct
	OP_MEM,		// immediate (inline), other mem indirects
	OP_CONST,	// cg-/sr-based specials
	OP_FLAGSONLY,	// cmp
	OP_SYMBOLIC,
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

#ifdef REALLYFAST

#define _MASK(N) ((1U << (N)) - 1)
#define bits(N, H, L) \
    ((N) & _MASK(H+1) & ~_MASK(L))

#define memwriteword(addr, word) (memword(addr) = (word))
#define memword(addr) (*(uint16_t*)&memory[(addr) & 0xffff])

#endif

#if SYMBOLIC
#define STATIC_PATTERN(n, s) \
static struct sexp *n;					\
static void __attribute__ ((constructor))	\
_init_pattern_ ## n (void)			\
{						\
						\
	n = (s);				\
}

struct sexp	*peephole(struct sexp *s);
bool		 isregsym(uint16_t reg);
bool		 ismemsym(uint16_t addr, uint16_t bw);
struct sexp	*regsym(uint16_t reg);
struct sexp	*memsym(uint16_t addr, uint16_t bw);
void		 printsym(struct sexp *sym);
void		 memwritesym(uint16_t addr, uint16_t bw, struct sexp *s);
void		 delmemsyms(uint16_t addr, uint16_t bw);
struct sexp	*mksexp(enum sexp_kind sk, unsigned nargs, ...);
struct sexp	*sexp_alloc(enum sexp_kind skind);
struct sexp	*sexp_imm_alloc(uint16_t n);
bool		 sexp_eq(struct sexp *s, struct sexp *t);
void		 sexp_flags(struct sexp *flags, uint16_t *set, uint16_t *clr);
struct sexp	*mkinp(unsigned i);
struct sexp	*subsexp(struct sexp **out);
struct sexp	*subimm(uint16_t *out);
bool		 sexpmatch(struct sexp *needle, struct sexp *haystack);
#endif

void		 abort_nodump(void);
void		 init(void);
void		 callgate(unsigned op);
void		 win(void);
void		 destroy(void);
void		 emulate(void);
void		 emulate1(void);
uint16_t	 membyte(uint16_t addr);
#ifndef REALLYFAST
uint16_t	 memword(uint16_t addr);
void		 memwriteword(uint16_t addr, uint16_t word);
#endif
void		 mem2reg(uint16_t addr, unsigned reg);
void		 reg2mem(unsigned reg, uint16_t addr);
#ifndef REALLYFAST
uint16_t	 bits(uint16_t v, unsigned max, unsigned min);
#endif
#ifdef BF
#define unhandled(instr) do { _unhandled(__FILE__, __LINE__, instr); return; } while (false)
#else
#define unhandled(instr) _unhandled(__FILE__, __LINE__, instr)
#endif
void		 _unhandled(const char *f, unsigned l, uint16_t instr);
#ifdef BF
#define illins(instr) do { _illins(__FILE__, __LINE__, instr); return; } while (false)
#else
#define illins(instr) _illins(__FILE__, __LINE__, instr)
#endif
void		 _illins(const char *f, unsigned l, uint16_t instr);
void		 inc_reg(uint16_t reg, uint16_t bw);
void		 dec_reg(uint16_t reg, uint16_t bw);
void		 print_regs(void);
uint16_t	 sr_flags(void);
#ifndef REALLYFAST
void		 addflags(unsigned res, uint16_t orig, uint16_t *set,
			  uint16_t *clr);
#endif
void		 andflags(uint16_t res, uint16_t *set, uint16_t *clr);
uint64_t	 now(void);	// microseconds
void		 getsn(uint16_t addr, uint16_t len);
void		 depcheck(uint16_t addr, unsigned perm);

void	handle_jump(uint16_t instr);
void	handle_single(uint16_t instr);
void	handle_double(uint16_t instr);

void	load_src(uint16_t instr, uint16_t instr_decode_src,
		 uint16_t As, uint16_t bw, uint16_t *srcval,
		 enum operand_kind *srckind);
void	load_dst(uint16_t instr, uint16_t instr_decode_dst,
		 uint16_t Ad, uint16_t *dstval,
		 enum operand_kind *dstkind);

void	print_ips(void);

// GDB stuff
void	gdbstub_init(void);
void	gdbstub_intr(void);
void	gdbstub_stopped(void);
void	gdbstub_interactive(void);
void	gdbstub_breakpoint(void);

#ifdef REALLYFAST
inline void
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
	*clr |= 0xfe00;
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
#endif

#endif
