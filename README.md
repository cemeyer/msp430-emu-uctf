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

GDB
===

Invoke `msp430-emu -g <romfile>` to wait for GDB on startup. Use `msp430-gdb`
to connect (mspgcc patchset on top of gdb-7.2a) with:

    msp430-gdb -ex 'target remote localhost:3713'

Supported commands are reading/writing registers and memory, stepping,
continue, and breakpoints.

Stepping Backwards
==================

In gdb, you can use `reverse-stepi` (or `rsi` for short) to step backwards. For
example (from Hanoi):

    $ msp430-gdb -nx -ex 'target remote localhost:3713' -ex 'display/i $pc'

    0x00004400 in ?? ()
    1: x/i $pc
    => 0x4400:      mov     #17408, r1      ;#0x4400
    (gdb) b *0x4540
    Breakpoint 1 at 0x4540
    (gdb) c
    Continuing.
    Breakpoint 1, 0x00004540 in ?? ()
    1: x/i $pc
    => 0x4540:      mov     #9216,  r15     ;#0x2400
    (gdb) rsi
    0x000045dc in ?? ()
    1: x/i $pc
    => 0x45dc:      ret
    (gdb) rsi
    0x000045d8 in ?? ()
    1: x/i $pc
    => 0x45d8:      add     #6,     r1      ;#0x0006
    (gdb) rsi
    0x00004590 in ?? ()
    1: x/i $pc
    => 0x4590:      ret
    (gdb) rsi
    0x0000458e in ?? ()
    1: x/i $pc
    => 0x458e:      pop     r2
    (gdb) rsi
    0x00000010 in ?? ()
    1: x/i $pc
    => 0x10:        ret
    (gdb) rsi
    0x0000458a in ?? ()
    1: x/i $pc
    => 0x458a:      call    #0x0010
    (gdb) rsi
    0x00004586 in ?? ()
    1: x/i $pc
    => 0x4586:      bis     #-32768,r2      ;#0x8000

TODO
====

- More advanced GDB integration (memory watchpoints, ...).

License
=======

msp430-emu-uctf is released under the terms of the MIT license. See LICENSE.
