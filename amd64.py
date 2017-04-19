import unicorn
import capstone

import utils

bits = 64

regs = [
    "rax", "rcx", "rdx", "rbx",
    "rsp", "rbp", "rsi", "rdi",
    "r8" , "r9" , "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rip"
]

unicorn_arch = unicorn.UC_ARCH_X86
unicorn_mode = unicorn.UC_MODE_64

capstone_arch = capstone.CS_ARCH_X86
capstone_mode = capstone.CS_MODE_64

unicorn_regs = {}
capstone_regs = {}

for reg in regs:
    unicorn_regs[reg] = getattr(unicorn.x86_const, "UC_X86_REG_" + reg.upper())
    capstone_regs[reg] = getattr(capstone.x86_const, "X86_REG_" + reg.upper())

instruction_pointer = "rip"
stack_pointer = "rsp"

ip = instruction_pointer
sp = stack_pointer

address_mask = 0x0000007fffffffff
page_mask = 0x0000007ffffff000
page_size = 0x1000

return_instructions = ["\xc3"]
alignment = 1

pack = utils.p64
unpack = utils.u64
