from unirop import *
from z3 import *
from capstone import *
from emulator import *
#from ropbuilder import *
from utils import *

_gadgets = [
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
        (0x1000a00, "5e5f5ac3")
    ]

if __name__ == "__main__":
    gadgets = []

    print "Gadgets:"
    for addr, code in _gadgets:
        code = code.decode("hex")
        gadget = RealGadget(amd64, addr, code)
        gadget.analyse()

        print "0x%016x: %s" % (addr, disasm(addr, code))
        print "Stack adjustment %d" % gadget.move

        for reg in gadget.arch.regs:
            if gadget.regs[reg] == ("mov", reg): continue
            print "%5s: %r" % (reg, gadget.regs[reg])

        gadgets.append(gadget)

    chain = StartGadget(amd64)
    chain = chain >> SMTGadget(amd64, gadgets, levels=2)
    chain = chain >> amd64Call(0x44444444, 0x1111, 0x2222, 0x3333)
#    chain = chain >> SMTGadget(amd64, gadgets, levels=20)
#    chain = chain >> ConstraintGadget(amd64, {
#            "rax": 0x4141414141414141,
#            "rcx": 0x4242424242424242,
#            "rdx": 0x4343434343434343,
#            "rbx": 0x4444444444444444,
#            "rsi": 0x4545454545454545,
#            "rdi": 0x4646464646464646,
#            "r13": 0x4747474747474747,
#            "r14": 0x4848484848484848,
#            "rip": 0x4949494949494949,
#        })

    model = chain.model()

    ins, outs, m = model

    if "gadgets" in outs:
        print "Gadgets used:"
        for gad in outs["gadgets"]:
            print hex(int(str(m.eval(gad))))

    ropchain = chain.use(model = model)

    from pwn import hexdump
    print "ROP chain:"
    print hexdump(ropchain)

    print "Checking:"
    emu = Emulator(amd64)
    for gadget in gadgets:
        emu.map_code(gadget.address, gadget.code)

    emu.setup_stack(0x41424000, 0x1000, ropchain)
    emu.run(0x1000108, 0x2000000)

    for reg in amd64.regs:
        print reg, hex(emu[reg])
