import unicorn
import capstone
import utils

bits = 32

regs = ["r%d" % i for i in range(16)]

unicorn_arch = unicorn.UC_ARCH_ARM
unicorn_mode = unicorn.UC_MODE_ARM

capstone_arch = capstone.CS_ARCH_ARM
capstone_mode = capstone.CS_MODE_ARM

unicorn_regs = {}
capstone_regs = {}

for reg in regs:
    unicorn_regs[reg] = getattr(unicorn.arm_const, "UC_ARM_REG_" + reg.upper())
    capstone_regs[reg] = getattr(capstone.arm_const, "ARM_REG_"+ reg.upper())

instruction_pointer = "r15"
stack_pointer = "r13"
ip = instruction_pointer
sp = stack_pointer

address_mask = 0xffffffff
page_mask = 0xfffff000
page_size = 0x1000

return_instructions = []
alignment = 4

pack = utils.p32
unpack = utils.u32
