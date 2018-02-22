import subprocess
import elftools
import elftools.elf
from elftools.elf.elffile import ELFFile
from emulator import *
from unirop import *

def load_gadgets(path, arch):
    gadgets = subprocess.check_output("ROPgadget --binary %s | grep -e \"0x[[:xdigit:]]* :\"" % path, shell=True)
    gadget_addrs = [int(gadget.split(":")[0].strip(), 16) for gadget in gadgets.strip().split("\n")]
    gadgets = {}
    with open(path, "r") as f:
        elf = ELFFile(f)
        for gadget_addr in gadget_addrs:
            offset = elf.address_offsets(gadget_addr).next()
            f.seek(offset)
            gadget_code = f.read(16)
            gadget = RealGadget(arch, gadget_addr, gadget_code) 
            gadget.analyse()
            if gadget.regs[arch.ip][0] == "junk": continue
            if gadget.regs[arch.sp][0] != "add": continue
            gadgets[gadget_addr] = gadget
    return gadgets

    

if __name__ == "__main__":
    import sys
    arch = __import__(sys.argv[2] if len(sys.argv) > 2 else "amd64")
    gadgets = load_gadgets(sys.argv[1], arch)
    print "Gadgets:"
    for gadget in gadgets.values():
        asm = disasm(gadget.arch, gadget.address, gadget.code)
        print "  0x%016x: %s" % (gadget.address, asm)
        print "    Stack adjustment %d" % gadget.move

        for reg in gadget.arch.regs:
            if gadget.regs[reg] == ("mov", reg): continue
            print "    %3s: %r" % (reg, gadget.regs[reg])
