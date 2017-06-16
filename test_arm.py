from unirop import *
from test_gadgets import arm_gadgets
from pwn import hexdump
import arm

gadgets = arm_gadgets.values()
arch = arm

pop_r1_r2_r7_pc = gadgets[0]
mov_r0_r2_pop_r7_pc = gadgets[1]
mov_r3_r0_bx_r7 = gadgets[2]

if __name__ == "__main__":
    chain = StartGadget(arch)
    chain = chain >> SMTGadget(arch, gadgets, levels = 6)
    chain = chain >> armCall(
            u32("FUNC"),
            u32("ARG1"),
            u32("ARG2"),
            u32("ARG3"),
            u32("ARG4")
        )
    model = chain.model()
    ins, outs, m = model

    #how did we do it?
    if "gadgets" in outs:
        print "Gadgets used:"
        for gadget in outs["gadgets"]:
            addr = int(str(m.eval(gadget)))
            gad = arm_gadgets[addr]
            print "0x%x: %s" % (addr, disasm(arch, addr, gad.code))

    # print the final result
    print "Ropchain:"
    ropchain = chain.use(model = model)
    print hexdump(ropchain)

