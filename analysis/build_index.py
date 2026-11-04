"""Build a capstone instruction index and a rip-relative/imm xref index.

NOTE (2026-11): `funcstarts.pkl` in this directory (derived from .eh_frame) is
UNRELIABLE and must not be used to attribute code to functions.  Cross-checks:

  * its 13430 entries intersect Ghidra's 13503 function entries in only 2 places;
  * most of its addresses are not instruction boundaries (e.g. 0x4b1784 has no
    instruction), and its maximum 0x969054 lies beyond .text end 0x94eb84;
  * Ghidra's entries are genuine prologues (0x4b1800 = push r15; push r14).

Use Ghidra's function list instead, converting with
    Ghidra address = ELF virtual address + 0x100000
(13263 of 13503 Ghidra functions fall inside the converted .text range).

The xref/instruction indexes this script builds are unaffected: they contain
real instruction addresses.  See REPORT.md section 6 and the reconstruction
repo's docs/02-module-map.md section 12.
"""
import sys, struct, bisect, pickle, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import Elf
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP

E = Elf(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'libgraphwarrust.so'))

def sweep():
    t = E.sec('.text')
    blob = E.data[t['offset']:t['offset'] + t['size']]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.syntax = CS_OPT_SYNTAX_INTEL
    insns = {}
    for ins in md.disasm(blob, t['addr']):
        insns[ins.address] = ins
    return insns

def xrefs(insns):
    """map target addr -> list of (insn_addr, kind, text)"""
    x = {}
    for a, ins in insns.items():
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tgt = ins.address + ins.size + op.mem.disp
                x.setdefault(tgt, []).append((a, 'rip', ins))
            elif op.type == X86_OP_IMM:
                v = op.imm
                if v > 0x1000:
                    x.setdefault(v & 0xffffffffffffffff, []).append((a, 'imm', ins))
    return x

if __name__ == '__main__':
    insns = sweep()
    print('insns', len(insns))
    x = xrefs(insns)
    print('xref targets', len(x))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'insns.pkl'), 'wb') as f:
        pickle.dump({a: (i.mnemonic, i.op_str, i.size, i.bytes) for a, i in insns.items()}, f, 2)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xrefs.pkl'), 'wb') as f:
        pickle.dump({t: [(a, k, i.mnemonic, i.op_str) for a, k, i in v] for t, v in x.items()}, f, 2)
