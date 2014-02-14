FLAGS=-Wall -Wextra -std=gnu99 -Wno-unused-function -Wno-unused-variable
SAFEFLAGS=$(FLAGS) -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4
#OPTFLAGS=`rpm -E %optflags` -O3
EXTRAFLAGS=
NEWGCCFLAGS=-grecord-gcc-switches
OPTFLAGS=-O3 -g -pipe -m64 -mtune=native -march=native -flto $(NEWGCCFLAGS)
DBGFLAGS=-O0 -g -pipe -m64 -mtune=native -march=native -flto $(NEWGCCFLAGS)
GLIB_FLAGS=`pkg-config --libs --cflags glib-2.0`
GLIB_LDFLAGS=`pkg-config --libs glib-2.0`

msp430-emu: main.c emu.h gdbstub.c
	gcc $(OPTFLAGS) $(SAFEFLAGS) $(GLIB_FLAGS) $< gdbstub.c -o $@

msp430-sym: main.c emu.h
	gcc $(OPTFLAGS) $(SAFEFLAGS) $(GLIB_FLAGS) -DSYMBOLIC=1 $< -o $@

check: check_instr
	./check_instr

check_instr: check_instr.c main.c emu.h
	gcc $(DBGFLAGS) $(FLAGS) $(GLIB_FLAGS) -DSYMBOLIC=1 -DEMU_CHECK $< main.c -lcheck $(GLIB_LDFLAGS) $(EXTRAFLAGS) -o $@

bfnovo: bfnovo.c main.c emu.h
	@rm -f *.gcda
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) -fprofile-generate -DSYMBOLIC=0 -DBF=1 -DEMU_CHECK -DQUIET -DREALLYFAST $< main.c -o prof-$@
	BF_GENERATE=1 ./prof-$@
	@rm -f ./prof-$@
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) -fprofile-use -DSYMBOLIC=0 -DBF=1 -DEMU_CHECK -DQUIET -DREALLYFAST $< main.c -o $@
	@rm -f *.gcda
