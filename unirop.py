import unicorn
import capstone
import random
import amd64
import logging
from emulator import Emulator
from z3 import *
from utils import *

def combine_regs(arch, fst, snd):
    out = {}
    for reg in arch.regs:
        out[reg] == ("junk",)
        if snd[reg][0] == "stack":
            out[reg] = ("stack", fst.move + snd[reg][1])
        if snd[reg][0] == "mov":
            out[reg] = fst[snd[reg][1]]
        if snd[reg][0] == "add" and fst[reg][0] == "add":
            out[reg] == ("add", snd[reg][1] + fst[reg][1])
    return out


class Gadget(object):
    def __init__(self, arch):
        self.arch = arch
        self.address = None
        self.analysed = False
        self._pops = {}
        self._movs = {}

    def __rshift__(self, next):
        return CompositGadget(self, next)

    @property
    def pops(self):
        assert self.analysed
        if not self._pops: 
            for reg, val in self.regs.items():
                if val[0] == "stack":
                    self._pops[reg] = val[1]
        return self._pops

    @property
    def movs(self):
        assert self.analysed
        if not self._movs:
            for reg, val in self.regs.items():
                if val[0] == "mov":
                    self._movs[reg] = val[1]
        return self._movs

    def use(self, model = None):
        if not model: model = self.model()
        ins, outs, m = model
        stack_size = outs["rsp"] - ins["rsp"]
        stack_size = int(str(m.eval(stack_size)))
        return z3_model_read_bytes(m, ins["stack"], 0, stack_size)

    def model(self):
        ins = z3_new_state(self.arch)
        outs = self.map(ins)
        s = Solver()
        s.add([
            ins[reg] == 0
            for reg in self.arch.regs
            if reg not in (self.arch.ip, self.arch.sp)
        ]) 
        s.add(outs["constraints"])
        assert s.check() == sat
        return ins, outs, s.model()

    def analyse(self):
        raise NotImplemented()

    def map(self, state):
        raise NotImplemented()


class NopGadget(Gadget):
    def __init__(self, arch):
        Gadget.__init__(self, arch)
        self.regs = {}

    def analyse(self):
        self.analysed = True

    def map(self, state):
        return state


class StartGadget(Gadget):
    def __init__(self, arch):
        Gadget.__init__(self, arch)

    def analyse(self):
        self.analysed = True

    def map(self, state):
        state = dict(state)
        state["constraints"] = list(state["constraints"])
        state[self.arch.ip] = z3_read_bits(state["stack"], 0, self.arch.bits)
        state[self.arch.sp] = state[self.arch.sp] + (self.arch.bits >> 3)
        state["stack"] = z3_read_bits(state["stack"], self.arch.bits)
        return state


class CompositGadget(Gadget):
    def __init__(self, *gadgets):
        assert len(gadgets) >= 1
        Gadget.__init__(self, gadgets[0].arch)
        self.gadgets = gadgets
        self.address = gadgets[0].address
        self.regs = {}
        self.move = 0

    def analyse(self):
        for gadget in self.gadget:
            gadget.analyse()
        self.regs = self.gadgets[0]
        for gadget in self.gadgets[1:]:
            self.regs = combine_regs(self.regs, gadget.regs)
        self.move = sum(gadget.move for gadget in self.gadgets)
        self.analysed = True

    def map(self, state):
        for gadget in self.gadgets:
            state = gadget.map(state)
        return state


class RealGadget(Gadget):
    def __init__(self, arch, address, code):

        self.arch = arch
        self.address = address
        self.code = code
        self.analysed = False
        self.regs = {}
        self.move = 0

    def analyse(self):
        ip = self.arch.instruction_pointer
        sp = self.arch.stack_pointer
        emu = Emulator(self.arch)

        emu.map_code(self.address, self.code)

        stack = get_random_page(self.arch)
        stack_data = cyclic(self.arch.page_size)

        emu.setup_stack(
                stack,
                self.arch.page_size,
                stack_data
            )

        init_regs = {}

        for reg in self.arch.regs:
            if reg in (ip, sp): continue
            val = self.arch.unpack(randoms(self.arch.bits >> 3))
            emu[reg] = val
            init_regs[val] = reg

        emu.run(self.address, len(self.code))

        for reg in self.arch.regs:
            self.regs[reg] = ("junk", )
            val = emu[reg]
            if init_regs.get(val, None):
                self.regs[reg] = ("mov", init_regs[val])
                continue
            offset = gen_find(self.arch.pack(val), stack_data)
            if offset != -1:
                self.regs[reg] = ("stack", offset)

        if self.regs[sp][0] == "junk":
            self.move = emu[self.arch.stack_pointer] - stack
            self.regs[sp] = ("add", self.move)

        self.analysed = True

    def map(self, ins):
        assert self.analysed
        outs = dict(ins)
        outs["constraints"] = list(ins["constraints"])
        outs["constraints"].append(ins[self.arch.ip] == self.address)
            
        for reg, action in self.regs.items():
            if action[0] == "mov":
                outs[reg] = ins[action[1]]
            elif action[0] == "stack":
                outs[reg] = z3_read_bits(ins["stack"], action[1]*8, self.arch.bits)
            elif action[0] == "add":
                outs[reg] = ins[reg] + action[1]
            elif action[0] == "junk":
                outs[reg] = randint(0, 2**self.arch.bits)

        if self.move >= 0:
            outs["stack"] = z3_read_bits(ins["stack"], self.move * 8)

        return outs


class ConstraintGadget(Gadget):
    def __init__(self, arch, constraints):
        Gadget.__init__(self, arch)
        self.constraints = constraints

    def map(self, state):
        state = dict(state)
        state["constraints"] = list(state["constraints"])

        for reg, val in self.constraints.items():
            state["constraints"].append(state[reg] == val)

        return state


class SMTGadget(Gadget):
    def __init__(self, arch, gadgets, levels = 1):
        Gadget.__init__(self, arch)
        self.gadgets = gadgets
        self.levels = levels

    def equal_states(self, a, b):
        regs = [a[reg] == b[reg] for reg in self.arch.regs]
        stack = [Extract(b["stack"].size()-1, 0, a["stack"]) == b["stack"]]
        return stack + regs

    def build_round(self, state):
        fini = z3_new_state(self.arch)
        fini["constraints"] = list(state["constraints"])
        state = state.copy()
        state["constraints"] = []
        for gadget in self.gadgets:
            outs = gadget.map(state)
            
            fini["constraints"].append(z3.Implies(
                state[self.arch.ip] == gadget.address,
                z3.And(outs["constraints"]+self.equal_states(fini, outs))
            ))

        fini["constraints"].append(
            Or([state[self.arch.ip] == gadget.address for gadget in self.gadgets])
        )
        return fini

    def map(self, state):
        gadgets = []
        for lvl in range(self.levels):
            gadgets.append(state[self.arch.ip])
            state = self.build_round(state)
        state["gadgets"] = gadgets
        return state


class amd64Call(Gadget):
    def __init__(self, address, *args):
        Gadget.__init__(self, amd64)
        self.address = address
        assert len(args) <= 6
        self.args = args

    def map(self, state):
        state = dict(state)
        state["constraints"] = list(state["constraints"])
        state["constraints"].append(state[self.arch.ip] == self.address)
        for reg, arg in zip(("rdi", "rsi", "rdx", "rcx", "r8", "r9"), self.args):
            state["constraints"].append(state[reg] == arg)
        return state


class i386Call(Gadget):
    def __init__(self, address, *args):
        Gadget.__init__(self, i386)
        self.address = address
        self.args = args
        self.move = 4

    def map(self, ins):
        outs = ins.copy()
        outs["constraints"] = list(ins["constraints"])
        outs["constraints"].append(ins[self.arch.ip] == self.address)
        outs[self.arch.ip] = z3_read_bits(ins["stack"], 0, self.arch.bits)

        outs["stack"] = z3_read_bits(ins["stack"], self.move * 8)

        for i, arg in enumerate(args):
            arg_stack = z3_read_bits(
                    outs["stack"],
                    i*self.arch.bits,
                    self.arch.bits)
            outs["constraints"].append(arg_stack == arg)

        return outs
