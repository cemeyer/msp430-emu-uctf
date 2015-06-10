FLAGS=-Wall -Wextra -std=gnu99 -Wno-unused-function -Wno-unused-variable -Wno-missing-field-initializers
SAFEFLAGS=$(FLAGS) -fexceptions
#OPTFLAGS=`rpm -E %optflags` -O3
EXTRAFLAGS=
NEWGCCFLAGS=-grecord-gcc-switches -fstack-protector-strong --param=ssp-buffer-size=4
OPTFLAGS=-O3 -g -pipe -m64 -mtune=native -march=native $(NEWGCCFLAGS)
DBGFLAGS=-O0 -g -pipe -m64 -mtune=native -march=native $(NEWGCCFLAGS)
GLIB_FLAGS=`pkg-config --cflags glib-2.0`
GLIB_LDFLAGS=`pkg-config --libs glib-2.0`

msp430-emu: main.c emu.h gdbstub.c
	cc $(OPTFLAGS) $(SAFEFLAGS) $(GLIB_FLAGS) $< gdbstub.c -o $@ $(GLIB_LDFLAGS)

msp430-sym: main.c emu.h gdbstub.c
	cc $(OPTFLAGS) $(SAFEFLAGS) $(GLIB_FLAGS) -DSYMBOLIC=1 $< gdbstub.c -o $@ $(GLIB_LDFLAGS)

check: check_instr
	./check_instr

check_instr: check_instr.c main.c emu.h
	cc $(DBGFLAGS) $(FLAGS) $(GLIB_FLAGS) -DSYMBOLIC=1 -DEMU_CHECK $< main.c -lcheck $(GLIB_LDFLAGS) $(EXTRAFLAGS) -o $@

clean:
	rm -f check_instr msp430-sym msp430-emu
