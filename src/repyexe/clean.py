# modified from https://github.com/mandiant/flare-bytecode_graph/blob/master/examples/bytecode_deobf_blog.py
# by Joshua Homan, Mandiant

import dis
from .bytecode_graph import BytecodeGraph

def clean_ROT_TWO(bcg):
    for current in bcg.nodes():
        if current.next is None:
            break
        if current.opcode == dis.opmap['ROT_TWO'] and \
                current.next.opcode == dis.opmap['ROT_TWO']:
            if current.next.xrefs != []:
                continue
            else:
                bcg.delete_node(current.next)
                bcg.delete_node(current)

def clean_ROT_THREE(bcg):
    for current in bcg.nodes():
        if current.next is None or current.next.next is None:
            break
        if current.opcode == dis.opmap['ROT_THREE'] and \
                current.next.opcode == dis.opmap['ROT_THREE'] and \
                current.next.next.opcode == dis.opmap['ROT_THREE']:

            if (current.next.xrefs != [] or current.next.next.xrefs != []) :
                continue
            else:
                bcg.delete_node(current.next.next)
                bcg.delete_node(current.next)
                bcg.delete_node(current)

def clean_LOAD_POP(bcg):
    for current in bcg.nodes():
        if current.next is None:
            break

        if current.opcode == dis.opmap['LOAD_CONST'] and \
                current.next.opcode == dis.opmap['POP_TOP']:

            if current.next.xrefs != []:
                continue
            else:
                bcg.delete_node(current.next)
                bcg.delete_node(current)

def clean_NOPS(bcg):
    for current in bcg.nodes():
        if current.opcode == dis.opmap['NOP']:
            bcg.delete_node(current)

def clean(code):
    bcg = BytecodeGraph(code)
    clean_ROT_TWO(bcg)
    clean_ROT_THREE(bcg)
    clean_LOAD_POP(bcg)
    clean_NOPS(bcg)
    return bcg.get_code()