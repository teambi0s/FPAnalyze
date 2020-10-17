from pwn import *
import sys

HOST = 0
PORT = 0
io=process('./Samples/sm1.out',env = {"LD_PRELOAD" : "./FPAnalyze.so"})

reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv(a)
s = lambda a : io.send(a)


if __name__=="__main__":
    gdb.attach(io,"""
            b *_init
            handle SIGSEGV nostop pass
            """)
    sl('123')
    io.interactive()
