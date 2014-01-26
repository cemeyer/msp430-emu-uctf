FLAGS=-Wall -Wextra -std=gnu99 -Wno-unused-function -Wno-unused-variable
SAFEFLAGS=-Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4
#OPTFLAGS=`rpm -E %optflags` -O3
NEWGCCFLAGS=-grecord-gcc-switches
OPTFLAGS=-O3 -g -pipe -m64 -mtune=native -march=native -flto $(NEWGCCFLAGS)
DBGFLAGS=-O0 -g -pipe -m64 -mtune=native -march=native -flto $(NEWGCCFLAGS)
GLIB_FLAGS=`pkg-config --libs --cflags glib-2.0`

msp430-emu: main.c emu.h
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) $< -o $@

check: check_instr.c main.c emu.h
	gcc $(DBGFLAGS) $(FLAGS) $(GLIB_FLAGS) $< -lcheck -DEMU_CHECK main.c -o check_instr
	./check_instr

bfhw: bfhw.c main.c emu.h
	@rm -f *.gcda
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) -fprofile-generate $< -lcheck -DEMU_CHECK -DQUIET -DREALLYFAST main.c -o $@
	BFHW_GENERATE=1 ./bfhw
	gcc $(OPTFLAGS) $(FLAGS) $(GLIB_FLAGS) -fprofile-use $< -lcheck -DEMU_CHECK -DQUIET -DREALLYFAST main.c -o $@
	@rm -f *.gcda

bfhw_profile: bfhw.c main.c emu.h
	@rm -f *.gcda
	gcc $(DBGFLAGS) $(FLAGS) $(GLIB_FLAGS) -O1 -fprofile-generate $< -lcheck -DEMU_CHECK -DREALLYFAST main.c -o bfhw_prof
	BFHW_GENERATE=1 ./bfhw_prof
	gcc $(DBGFLAGS) $(FLAGS) $(GLIB_FLAGS) -O1 -fprofile-use $< -lcheck -DEMU_CHECK -DREALLYFAST main.c -o bfhw_prof
	@rm -f *.gcda
	valgrind --tool=callgrind ./bfhw_prof
