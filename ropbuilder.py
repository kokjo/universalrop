from z3 import *
from utils import *
from unirop import *


def build_rop_round(arch, gadgets, state, prefix=""):
    fini = z3_new_state(arch, prefix+"post_")
    fini["constraints"] = list(state["constraints"])
    fini["constraints"].append(
        Or([state[arch.ip] == gadget.address for gadget in gadgets])
    )
    state = state.copy()
    state["constraints"] = []
    for gadget in gadgets:
        outs = gadget.map(state)

        fini["constraints"].append(Implies(
            state[arch.ip] == gadget.address,
            And(outs["constraints"] + equal_states(arch, fini, outs))
        ))

    return fini

def build_rop_circuit(arch, gadgets, state, levels = 1):
    for lvl in range(levels):
        state = build_rop_round(arch, gadgets, state, "round%d_" % lvl)
    return state
