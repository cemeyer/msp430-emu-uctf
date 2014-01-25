FLAGS=-Wall -Wextra -std=gnu99
#OPTFLAGS=`rpm -E %optflags` -O3
OPTFLAGS=-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches  -m64 -mtune=generic
DBGFLAGS=-O0 -g -pipe -Wall -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches  -m64 -mtune=generic
GLIB_FLAGS=`pkg-config --libs --cflags glib-2.0`

msp430-emu: main.c emu.h
	gcc $(FLAGS) $(OPTFLAGS) $(GLIB_FLAGS) $< -o $@

check: check_instr.c main.c emu.h
	gcc $(FLAGS) $(DBGFLAGS) $(GLIB_FLAGS) $< -lcheck -DEMU_CHECK main.c -o check_instr
	./check_instr

bfhw: bfhw.c main.c emu.h
	gcc $(FLAGS) $(OPTFLAGS) $(GLIB_FLAGS) $< -lcheck -DEMU_CHECK -DQUIET main.c -o $@
