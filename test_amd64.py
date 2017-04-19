from unirop import *
from test_gadgets import amd64_gadgets 
from pwn import hexdump
import amd64

gadgets = amd64_gadgets.values()
arch = amd64

if __name__ == "__main__":
    # pop the first gadget of the stack
    chain = StartGadget(arch)
    # create a rop chain of length 7 using all the gadgets in `gadgets`
    chain = chain >> SMTGadget(arch, gadgets, levels=7)
    # add some constraints for doing a function call
    chain = chain >> amd64Call(
            u64("RIP=FUNC"), # what to call?
            u64("RDI=ARG1"), # first argument
            u64("RSI=ARG2"), # secound argument 
            u64("RDX=ARG3")  # ...
        )
    # check if this is possible, and generated a model of it
    model = chain.model()
    ins, outs, m = model
    
    #how did we do it?
    if "gadgets" in outs:
        print "Gadgets used:"
        for gadget in outs["gadgets"]:
            addr = int(str(m.eval(gadget)))
            gad = amd64_gadgets[addr]
            print "0x%x: %s" % (addr, disasm(arch, addr, gad.code))

    # print the final result
    print "Ropchain:"
    ropchain = chain.use(model = model)
    print hexdump(ropchain)
