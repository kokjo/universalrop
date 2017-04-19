import unicorn
import capstone

bits = 32

regs = [
    "eax", "ecx", "edx", "ebx",
    "esp", "ebp", "esi", "edi",
    "eip"
]

unicorn_arch = unicorn.UC_ARCH_X86
unicorn_mode = unicorn.UC_MODE_32

unicorn_regs = {}
capstone_regs = {}

for reg in regs:
    unicorn_regs[reg] = getattr(unicorn.x86_const, "UC_X86_REG_" + reg.upper())
    capstone_regs[reg] = getattr(capstone.x86_const, "X86_REG_" + reg.upper())

instruction_pointer = "eip"
stack_pointer = "esp"

ip = instruction_pointer
sp = stack_pointer

address_mask = 0xffffffff
page_mask = 0xfffff000
page_size = 0x1000

return_instructions = ["\xc3"]
alignment = 1

pack = utils.p32
unpack = utils.u32
