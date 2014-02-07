FLAGS=-Wall -Wextra -std=gnu99 -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter
SAFEFLAGS=$(FLAGS) -lrt 
#OPTFLAGS=`rpm -E %optflags` -O3
EXTRAFLAGS=
NEWGCCFLAGS=-grecord-gcc-switches
OPTFLAGS=-O3 -g -pipe -m64 -mtune=native -march=native -flto $(NEWGCCFLAGS)
DBGFLAGS=-O0 -g -pipe -m64 -mtune=native -march=native -flto $(NEWGCCFLAGS)
GLIB_FLAGS=`pkg-config --libs --cflags glib-2.0`
GLIB_LDFLAGS=`pkg-config --libs glib-2.0`

msp430-emu: main.c emu.h
	gcc $(OPTFLAGS) $(SAFEFLAGS) $(GLIB_FLAGS) $< -o $@

msp430-sym: main.c emu.h
	gcc $(OPTFLAGS) $(SAFEFLAGS) $(GLIB_FLAGS) -DSYMBOLIC=1 $< -o $@

check: check_instr
	./check_instr

check_instr: check_instr.c main.c emu.h
	gcc $(DBGFLAGS) $(FLAGS) $(GLIB_FLAGS) -DSYMBOLIC=1 -DEMU_CHECK $< main.c -lcheck $(GLIB_LDFLAGS) $(EXTRAFLAGS) -o $@

bfhw: bfhw.c main.c emu.h
	@rm -f *.gcda
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) -fprofile-generate -DBF=1 -DSYMBOLIC=0 -DEMU_CHECK -DQUIET -DREALLYFAST $< main.c -o prof-$@
	BFHW_GENERATE=1 ./prof-$@
	@rm -f ./prof-$@
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) -fprofile-use -DBF=1 -DSYMBOLIC=0 -DEMU_CHECK -DQUIET -DREALLYFAST $< main.c -o $@
	@rm -f *.gcda

bfhw_profile: bfhw.c main.c emu.h
	@rm -f *.gcda
	gcc $(DBGFLAGS) $(FLAGS) $(GLIB_FLAGS) -O1 -fprofile-generate -DBF=1 -DSYMBOLIC=0 -DEMU_CHECK -DREALLYFAST $< main.c -o bfhw_prof
	BFHW_GENERATE=1 ./bfhw_prof
	gcc $(DBGFLAGS) $(FLAGS) $(GLIB_FLAGS) -O1 -fprofile-use -DBF=1 -DSYMBOLIC=0 -DEMU_CHECK -DREALLYFAST $< main.c -o bfhw_prof
	@rm -f *.gcda
	valgrind --tool=callgrind ./bfhw_prof

bfnovo: bfnovo.c main.c emu.h
	@rm -f *.gcda
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) -fprofile-generate -DSYMBOLIC=0 -DBF=1 -DEMU_CHECK -DQUIET -DREALLYFAST $< main.c -o prof-$@
	BF_GENERATE=1 ./prof-$@
	@rm -f ./prof-$@
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) -fprofile-use -DSYMBOLIC=0 -DBF=1 -DEMU_CHECK -DQUIET -DREALLYFAST $< main.c -o $@
	@rm -f *.gcda
