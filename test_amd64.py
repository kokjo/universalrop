from unirop import *
from test_gadgets import amd64_gadgets 
from pwn import hexdump
import amd64

gadgets = amd64_gadgets.values()
arch = amd64

if __name__ == "__main__":
    chain = StartGadget(arch)
    chain = chain >> SMTGadget(arch, gadgets, levels=7)
    chain = chain >> amd64Call(
            u64("RIP=FUNC"),
            u64("RDI=ARG1"),
            u64("RSI=ARG2"),
            u64("RDX=ARG3")
        )

    model = chain.model()
    ins, outs, m = model

    if "gadgets" in outs:
        print "Gadgets used:"
        for gadget in outs["gadgets"]:
            addr = int(str(m.eval(gadget)))
            gad = amd64_gadgets[addr]
            print "0x%x: %s" % (addr, disasm(arch, addr, gad.code))

    print "Ropchain:"
    ropchain = chain.use(model = model)
    print hexdump(ropchain)
