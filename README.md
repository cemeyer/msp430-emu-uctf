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

TODO
====

- More advanced GDB integration (memory watchpoints, ...).

License
=======

msp430-emu-uctf is released under the terms of the MIT license. See LICENSE.
