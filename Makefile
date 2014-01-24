FLAGS=-Wall -Wextra -std=gnu99
OPTFLAGS=`rpm -E %optflags` -O3
GLIB_FLAGS=`pkg-config --libs --cflags glib-2.0`

msp430-emu: main.c emu.h
	gcc $(FLAGS) $(OPTFLAGS) $(GLIB_FLAGS) $< -o $@

check: check_instr.c main.c emu.h
	gcc $(FLAGS) $(OPTFLAGS) $(GLIB_FLAGS) $< -lcheck -DEMU_CHECK main.c -o check_instr
	./check_instr

bfhw: bfhw.c main.c emu.h
	gcc $(FLAGS) $(OPTFLAGS) $(GLIB_FLAGS) $< -lcheck -DEMU_CHECK -DAUTO_GETSN -DQUIET main.c -o $@
