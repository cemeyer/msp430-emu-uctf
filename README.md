msp430-emu-uctf [![Build Status](https://travis-ci.org/cemeyer/msp430-emu-uctf.png?branch=master)](https://travis-ci.org/cemeyer/msp430-emu-uctf)
===================

This is an msp430-alike emulator for Matasano/Square's #µctf. It faithfully
emulates the inaccurate flags behavior of the real thing
(http://microcorruption.com/). It's pretty fast (~48 M Instr/sec on 3 GHz
Haswell Xeon), and certainly faster than the real thing (25 MHz, with 2-3
cycles per instruction).

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

License
=======

msp430-emu-uctf is released under the terms of the MIT license. See LICENSE.
Basically, do what you will with it. If you want to throw credit, money, or
praise my way, I would love it. I am also happy to get negative feedback. Let
me know what you would like to see improved!
