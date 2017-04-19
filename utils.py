import string
import struct
import itertools
import random
import z3
import capstone

alphabet = "".join(chr(i) for i in range(256))
alphabet = string.ascii_lowercase

def p64(v): return struct.pack("<Q", v)
def p32(v): return struct.pack("<L", v)

def u64(v): return struct.unpack("<Q", v)[0]
def u32(v): return struct.unpack("<L", v)[0]

def disasm(arch, addr, code):
    cs = capstone.Cs(arch.capstone_arch, arch.capstone_mode)
    insts = ['%s %s' % (inst.mnemonic, inst.op_str) for inst in cs.disasm(bytes(code), addr)]
    return "; ".join(insts)

def de_bruijn(alphabet = alphabet, n=8):
    k = len(alphabet)
    a = [0] * k * n
    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    yield alphabet[a[j]]
        else:
            a[t] = a[t - p]
            for c in db(t + 1, p):
                yield c

            for j in range(a[t - p] + 1, k):
                a[t] = j
                for c in db(t + 1, t):
                    yield c

    return db(1,1)

def cyclic(length, alphabet = alphabet, n=8):
    out = []
    for i, c in enumerate(de_bruijn(alphabet, n)):
        if length <= i: break
        out.append(c)
    return "".join(out)

def cyclic_find(length, substr, alphabet = alphabet, n=8):
    if any(c not in alphabet for c in substr):
        return -1
    return _gen_find(substr, cyclic(length, alphabet, n))

def gen_find(subseq, generator):
    subseq = list(subseq)
    pos = 0
    saved = []

    for c in generator:
        saved.append(c)
        if len(saved) > len(subseq):
            saved.pop(0)
            pos += 1
        if saved == subseq:
            return pos
    return -1

def fit(size, fits, padding="A"):
    padding = itertools.cycle(padding)
    data = "".join(itertools.islice(padding, size))
    for off, val in fits.items():
        data = data[:off] + val + data[off + len(val):]
    return data 

def randoms(count, alphabet = alphabet):
    return ''.join(random.choice(alphabet) for _ in xrange(count))


def get_random_page(arch):
    addr = random.randint(0, 2**(arch.bits-1))
    addr &= arch.page_mask
    return addr

def z3_read_bits(bv, offset, size=None):
    if not size:
        size = bv.size() - offset
    return z3.Extract(int(offset + size - 1), int(offset), bv)

def z3_model_read_bytes(model, bv, offset, size):
    data = []
    for i in xrange(size):
        byte = z3_read_bits(bv, (offset + i)*8, 8)
        data.append(chr(int(str(model.eval(byte)))))
    return "".join(data)

unique_counter = 0
def unique(s):
    global unique_counter
    unique_counter += 1
    return "%s_%d" % (s, unique_counter)

def z3_new_state(arch):
    state = {
        "stack": z3.BitVec(unique("stack"), arch.page_size*8),
        "constraints": []
    }

    for reg in arch.regs:
        state[reg] = z3.BitVec(unique(reg), arch.bits)

    return state
