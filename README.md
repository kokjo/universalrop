```console
$ time python test.py
Gadgets:
0x0000000001000100: pop rbx; pop rbp; pop r12; pop r13; pop r14; ret 
Stack adjustment 48
  rbx: ('stack', 0)
  rsp: ('add', 48L)
  rbp: ('stack', 8)
  r12: ('stack', 16)
  r13: ('stack', 24)
  r14: ('stack', 32)
  rip: ('stack', 40)
0x0000000001000101: pop rbp; pop r12; pop r13; pop r14; ret 
Stack adjustment 40
  rsp: ('add', 40L)
  rbp: ('stack', 0)
  r12: ('stack', 8)
  r13: ('stack', 16)
  r14: ('stack', 24)
  rip: ('stack', 32)
0x0000000001000102: pop r12; pop r13; pop r14; ret 
Stack adjustment 32
  rsp: ('add', 32L)
  r12: ('stack', 0)
  r13: ('stack', 8)
  r14: ('stack', 16)
  rip: ('stack', 24)
0x0000000001000104: pop r13; pop r14; ret 
Stack adjustment 24
  rsp: ('add', 24L)
  r13: ('stack', 0)
  r14: ('stack', 8)
  rip: ('stack', 16)
0x0000000001000106: pop r14; ret 
Stack adjustment 16
  rsp: ('add', 16L)
  r14: ('stack', 0)
  rip: ('stack', 8)
0x0000000001000108: ret 
Stack adjustment 8
  rsp: ('add', 8L)
  rip: ('stack', 0)
0x0000000001000200: mov rdi, rax; pop rbx; ret 
Stack adjustment 16
  rbx: ('stack', 0)
  rsp: ('add', 16L)
  rdi: ('mov', 'rax')
  rip: ('stack', 8)
0x0000000001000203: pop rbx; ret 
Stack adjustment 16
  rbx: ('stack', 0)
  rsp: ('add', 16L)
  rip: ('stack', 8)
0x0000000001000400: xor rax, rax; pop rbx; add rax, rdi; ret 
Stack adjustment 16
  rax: ('mov', 'rdi')
  rbx: ('stack', 0)
  rsp: ('add', 16L)
  rip: ('stack', 8)
0x0000000001000500: mov rax, r13; ret 
Stack adjustment 8
  rax: ('mov', 'r13')
  rsp: ('add', 8L)
  rip: ('stack', 0)
0x0000000001000600: mov rcx, rdx; ret 
Stack adjustment 8
  rcx: ('mov', 'rdx')
  rsp: ('add', 8L)
  rip: ('stack', 0)
0x0000000001000700: pop rdx; jmp rax
Stack adjustment 8
  rdx: ('stack', 0)
  rsp: ('add', 8L)
  rip: ('mov', 'rax')
0x0000000001000800: mov rcx, rdx; jmp rbx
Stack adjustment 0
  rcx: ('mov', 'rdx')
  rsp: ('add', 0L)
  rip: ('mov', 'rbx')
0x0000000001000900: pop rsi; jmp rdi
Stack adjustment 8
  rsp: ('add', 8L)
  rsi: ('stack', 0)
  rip: ('mov', 'rdi')
0x0000000001000a00: pop rsi; pop rdi; pop rdx; ret 
Stack adjustment 32
  rdx: ('stack', 16)
  rsp: ('add', 32L)
  rsi: ('stack', 0)
  rdi: ('stack', 8)
  rip: ('stack', 24)
Gadgets used:
0x1000500
0x1000a00
ROP chain:
00000000  00 05 00 01  00 00 00 00  00 0a 00 01  00 00 00 00  │····│····│····│····│
00000010  22 22 00 00  00 00 00 00  11 11 00 00  00 00 00 00  │""··│····│····│····│
00000020  33 33 00 00  00 00 00 00  44 44 44 44  00 00 00 00  │33··│····│DDDD│····│
00000030
Checking:
rax 0x0
rcx 0x0
rdx 0x3333
rbx 0x0
rsp 0x41424030
rbp 0x0
rsi 0x2222
rdi 0x1111
r8 0x0
r9 0x0
r10 0x0
r11 0x0
r12 0x0
r13 0x0
r14 0x0
r15 0x0
rip 0x44444444

real    0m7.373s
user    0m7.072s
sys 0m0.300s
```
