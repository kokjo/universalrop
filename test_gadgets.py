from emulator import *
from unirop import *
import x86, amd64

_amd64_gadgets = [
#        (0x1000100, "5b5d415c415d415ec3"),
#        (0x1000101, "5d415c415d415ec3"),
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
        (0x1000100, "585f83c410c3")
    ]

def analyse_gadget(arch, addr, code):
    gadget = RealGadget(arch, addr, code)
    gadget.analyse()
    return gadget

amd64_gadgets = {addr: analyse_gadget(amd64, addr, code.decode("hex"))
        for addr, code in _amd64_gadgets}
x86_gadgets = {addr: analyse_gadget(x86, addr, code.decode("hex"))
        for addr, code in _x86_gadgets}

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
