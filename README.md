msp430-emu-uctf [![Build Status](https://travis-ci.org/cemeyer/msp430-emu-uctf.png?branch=master)](https://travis-ci.org/cemeyer/msp430-emu-uctf)
===================

This is an msp430-alike emulator for Matasano/Square's #µctf.

What can I do with it?
======================

* Use it to debug or solve Microcorruption puzzles offline
* Use it to debug or emualate other trivial MSP430 embedded programs (with the
  same weird register and callgate behavior of Microcorruption...)
* Embed it into something weirder and cooler! I don't even know.

Why not mspsim, mspdebug?
=========================

msp430-emu-uctf (that's a mouthful, isn't it) faithfully emulates the
inaccurate flags and instruction decode behavior of the
[Microcorruption](http://microcorruption.com/) web emulator and debugger. This
is useful on many #µctf levels. It also has enough of the callgate (0x0010)
implemented to successfully debug and defeat all of the puzzles.

Without making any comparison to the speed of mspsim or mspdebug,
msp430-emu-uctf is decently fast (emulates about 48 Million msp430 instructions
per second on my Intel E3-1240v3), and is probably faster than any hardware
MSP430 ever built (typically they are 25 MHz, with 2-3 cycles per instruction).

Building
========

`make` will build the emulator, `msp430-emu`.

This is not packaged for installation at this time. Patches welcome.

Simple Emulation
================

Invoke `msp430-emu <romfile>`.

Tracing
=======

Use the `-t=TRACE_FILE` option to `msp430-emu` to log a binary trace of all
instructions executed to `TRACE_FILE`. Use the `-x` flag to dump in hex format
instead of binary.

GDB: Installing msp430-gdb
==========================

First, you will need to install `msp430-gdb`. Many Linux distributions have
this as a package (sometimes under the name `gdb-msp430`).

If you don't have it as a distro package, you can download the gdb-7.2a sources
from a GNU mirror, apply the mspgcc-2012xxx-gdb patches against those sources,
and configure with something like `--program-prefix=msp430- --prefix=$HOME/.local`
for a `msp430-gdb` tool installed in your `$HOME` directory.

GDB: Debugging Emulated ROMs
============================

Invoke `msp430-emu -g <romfile>` to wait for GDB on startup. The emulator binds
TCP port 3713 and waits for the first client to connect. Use `msp430-gdb` from
another terminal to connect (mspgcc patchset on top of gdb-7.2a) with:

    msp430-gdb -ex 'target remote localhost:3713'

Supported commands are:
* reading/writing registers
* reading/writing memory
* (instruction) stepping, reverse-stepping
* breakpoints, continue

TODO:
* Memory watchpoints
* reverse-continue

GDB: Reverse debugging
======================

In gdb, you can use `reverse-stepi` (or `rsi` for short) to step backwards. For
example (from Hanoi):

    $ msp430-gdb -nx -ex 'target remote localhost:3713'

    (gdb) x/i $pc
    => 0x4400: mov #17408, r1 ;#0x4400

The next instruction will put 0x4400 in `r1` (`SP`).

    (gdb) p $r1
    $1 = (void *) 0x0

Do it...

    (gdb) si
    0x00004404 in ?? ()

    (gdb) p $r1
    $2 = (void *) 0x4400

Ok, it is set to 0x4400 now.

    (gdb) rsi
    0x00004400 in ?? ()

Go back one instruction.

    (gdb) p $r1
    $3 = (void *) 0x0

It's no longer set!

Symbolic Emulation
==================

`make msp430-sym` will build the symbolic emulator.

Caveat: symbolic execution is much, much slower than direct emulation.

To run a level in symbolic mode, invoke the emulator like so:

    msp430-sym <romfile> <input length>

This mode is less tested. On some levels you will see that register or PC loads
are dependent on symbolic inputs -- that means your input controls register
contents or code flow (exploitable!).

On Hollywood, with the right input size, this will emit gibberish. But that
gibberish is not too far from the truth. I recommend using the tracing mode to
defeat Hollywood, rather than trying to parse the symbolic output.

License
=======

msp430-emu-uctf is released under the terms of the MIT license. See LICENSE.
Basically, do what you will with it. If you want to throw credit, money, or
praise my way, I would love it. I am also happy to get negative feedback. Let
me know what you would like to see improved!

Hacking
=======

Try it out! Let me know what you don't like; send me patches, or file issues. I
can't promise I'll fix anything quickly, but I'd rather know what's wrong.

Style: The C sources attempt to follow BSD's
[style(9)](http://www.freebsd.org/cgi/man.cgi?query=style&sektion=9). Style fix
patches are welcome.

Most of the emulator (including symbolic mode) lives in `main.c`. Most of the
GDB remote stub lives in `gdbstub.c`. There are instruction emulation and
symbolic mode optimization unit tests in `check_instr.c`.
