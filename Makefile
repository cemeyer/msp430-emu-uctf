FLAGS=-Wall -Wextra -std=gnu99
OPTFLAGS=`rpm -E %optflags`
GLIB_FLAGS=`pkg-config --libs --cflags glib-2.0`

msp430-emu: main.c
	gcc $(FLAGS) $(OPTFLAGS) $(GLIB_FLAGS) $< -o $@
