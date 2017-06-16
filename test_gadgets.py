from emulator import *
from unirop import *
import x86, amd64, arm

_amd64_gadgets = [
        (0x1000100, "5b5d415c415d415ec3"),
        (0x1000101, "5d415c415d415ec3"),
        (0x1000102, "415c415d415ec3"),
        (0x1000104, "415d415ec3"),
        (0x1000106, "415ec3"),
        (0x1000108, "c3"),
        (0x1000200, "4889c75bc3"),
        (0x1000203, "5bc3"),
        (0x1000400, "4831c05b4801f8c3"),
        (0x1000500, "4c89e8c3"),
        (0x1000600, "4889d1c3"),
        (0x1000700, "5affe0"),
        (0x1000800, "4889d1ffe3"),
        (0x1000900, "5effe7"),
        (0x1000a00, "5ec3"),
    ]

_x86_gadgets = [
        (0x1000000, "c3"),
        (0x1000100, "585f83c410c3"),
    ]

_arm_gadgets = [
        (0x1000, "8680bde8"),
        (0x1010, "0200a0e18080bde8"),
        (0x1020, "0030a0e117ff2fe1"),
    ]

def analyse_gadget(arch, addr, code):
    gadget = RealGadget(arch, addr, code)
    gadget.analyse()
    return gadget

def analyse_gadgets(arch, gadgets):
    return {addr: analyse_gadget(arch, addr, code.decode("hex")) for addr, code in gadgets}

amd64_gadgets = analyse_gadgets(amd64, _amd64_gadgets)
x86_gadgets = analyse_gadgets(x86, _x86_gadgets)
arm_gadgets = analyse_gadgets(arm, _arm_gadgets)

def print_gadgets(name, arch, gadgets):
    print name, "Gadgets"
    for gadget in gadgets.values():
        print "  0x%016x: %s" % (gadget.address, disasm(arch, gadget.address, gadget.code))
        print "    Stack adjustment %d" % gadget.move

        for reg in gadget.arch.regs:
            if gadget.regs[reg] == ("mov", reg): continue
            print "    %3s: %r" % (reg, gadget.regs[reg])

if __name__ == "__main__":
    print_gadgets("amd64", amd64, amd64_gadgets)
    print_gadgets("x86", x86, x86_gadgets)
    print_gadgets("arm", arm, arm_gadgets)
