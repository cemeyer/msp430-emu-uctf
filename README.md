msp430-emu-uctf [![Build Status](https://travis-ci.org/cemeyer/msp430-emu-uctf.png?branch=master)](https://travis-ci.org/cemeyer/msp430-emu-uctf)
===================

This is an msp430-alike emulator for Matasano/Square's #µctf. It faithfully
emulates the inaccurate flags behavior of the real thing
(http://microcorruption.com/). It's pretty fast (~48 M Instr/sec on 3 GHz
Haswell Xeon), and certainly faster than the real thing (25 MHz, with 2-3
cycles per instruction).

I tried to add symbolic execution to solve Hollywood, but alas, I am stupid.
Anyway, maybe it can help you.

Building
========

`make` will build the emulator, `msp430-emu`. `make msp430-sym` will build
the symbolic emulator.

Emulating
=========

Simply invoke `msp430-emu <romfile>` or `msp430-sym <romfile> <input length>`.

Tracing
=======

Use the `-t=TRACE_FILE` option to `msp430-emu` to log a binary trace of all
instructions executed to `TRACE_FILE`. Use the `-x` flag to dump in hex format
instead of binary.

GDB
===

Invoke `msp430-emu -g <romfile>` to wait for GDB on startup. Use `msp430-gdb`
to connect (mspgcc patchset on top of gdb-7.2a) with:

    msp430-gdb -ex 'target remote localhost:3713'

Supported commands are reading/writing registers and memory, stepping,
continue, and breakpoints.

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

TODO
====

- More advanced GDB integration (memory watchpoints, ...).

License
=======

msp430-emu-uctf is released under the terms of the MIT license. See LICENSE.
