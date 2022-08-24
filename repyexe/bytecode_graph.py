# modified from https://github.com/mandiant/flare-bytecode_graph/blob/master/bytecode_graph/bytecode_graph.py
# by Joshua Homan, Mandiant

import sys
if sys.version_info.major not in [2, 3]:
    raise NotImplementedError("Only Python 2 and 3 are supported")
import dis
import struct
from dis import opname
from types import CodeType

python36 = sys.version_info >= (3, 6)
extended_multiplier = 0x100 if python36 else 0x10000

def get_int(value):
    if sys.version_info.major == 3:
        assert isinstance(value, int)
        return value
    elif sys.version_info.major == 2:
        assert isinstance(value, str)
        return ord(value)

class Bytecode():
    '''
    Class to store individual instruction as a node in the graph
    '''
    def __init__(self, addr=None, buffer=None, prev=None, next=None, xrefs=[]):
        self.addr = addr

        if buffer:
            self.opcode = get_int(buffer[0])
            if python36:
                self.oparg = get_int(buffer[1])
            elif self.opcode >= dis.HAVE_ARGUMENT:
                self.oparg = get_int(buffer[1]) | (get_int(buffer[2]) << 8)
            else:
                self.oparg = None
        else:
            self.opcode = None
            self.oparg = None

        self.actualarg = self.oparg
        self.prev = prev
        self.next = next
        self.xrefs = []
        self.target = None
        self.lineno = None

    def __str__(self):
        return self.disassemble()

    def is_extendedarg(self):
        return self.opcode == dis.opmap["EXTENDED_ARG"]

    def len(self):
        '''
        Returns the length of the bytecode
        1 for no argument
        3 for argument
        '''
        if python36:
            return 2
        if self.opcode < dis.HAVE_ARGUMENT:
            return 1
        else:
            return 3

    def disassemble(self):
        '''
        Return disassembly of bytecode
        '''
        rvalue = "%04x " % self.addr
        rvalue += "%s " % self.hex()
        rvalue += opname[self.opcode].ljust(20)
        if self.opcode >= dis.HAVE_ARGUMENT:
            if self.oparg == self.actualarg:
                if python36:
                    rvalue += "%02x" % (self.actualarg)
                else:
                    rvalue += "%04x" % (self.actualarg)
            else:
                rvalue += "(%x)" % (self.actualarg)
        return rvalue

    def hex(self):
        '''
        Return ASCII hex representation of bytecode
        '''
        rvalue = "%02x" % self.opcode
        if python36:
            rvalue += "%02x" % self.oparg
        elif self.opcode >= dis.HAVE_ARGUMENT:
            rvalue += "%02x%02x" % \
                    (self.oparg & 0xff, (self.oparg >> 8) & 0xff)
        else:
            rvalue += "    "
        return rvalue

    def bin(self):
        '''
        Return bytecode string
        '''
        if python36:
            return struct.pack("<BB", self.opcode, self.oparg)
        elif self.opcode >= dis.HAVE_ARGUMENT:
            return struct.pack("<BH", self.opcode, self.oparg)
        else:
            return struct.pack("<B", self.opcode)

    def get_target_addr(self):
        '''
        Returns the target address for the current instruction based on the
        current address.
        '''
        if self.opcode in dis.hasjrel:
            return self.addr + self.len() + self.actualarg
        elif self.opcode in dis.hasjabs:
            return self.actualarg
        else:
            return None


class BytecodeGraph():
    def __init__(self, code, base=0):
        self.base = base
        self.code = code
        self.head = None
        self.parse_bytecode()
        self.apply_lineno()

    def __str__(self):
        return self.disassemble()

    def add_node(self, parent, bc, lnotab=None, change_target=False):
        '''
        Adds an instruction node to the graph
        '''
        # setup pointers for new node
        bc.next = parent.next
        bc.prev = parent
        if lnotab is None:
            bc.lineno = parent.lineno
        else:
            bc.lineno = lnotab

        if parent.next is not None:
            parent.next.prev = bc

        parent.next = bc

        if change_target:
            for x in bc.next.xrefs:
                x.target = bc
                bc.xrefs.append(x)

    def apply_labels(self, start=None):
        '''
        Find all JMP REL and ABS bytecode sequences and update the target
        within branch instruction and add xref to the destination.
        '''
        for current in self.nodes(start):
            current.xrefs = []
            current.target = None

        for current in self.nodes(start):
            label = current.get_target_addr()
            if label:
                if current not in self.bytecodes[label].xrefs:
                    self.bytecodes[label].xrefs.append(current)
                current.target = self.bytecodes[label]
            current = current.next
        return

    def apply_lineno(self):
        '''
        Parses the code object co_lnotab list and applies line numbers to
        bytecode. This is used to create a new co_lnotab list after modifying
        bytecode.
        '''
        byte_increments = [get_int(c) for c in self.code.co_lnotab[0::2]]
        line_increments = [get_int(c) for c in self.code.co_lnotab[1::2]]

        lineno = self.code.co_firstlineno
        addr = self.base
        linenos = []

        for byte_incr, line_incr in zip(byte_increments, line_increments):
            addr += byte_incr
            lineno += line_incr
            linenos.append((addr, lineno))

        if linenos == []:
            return

        current_lineno = self.code.co_firstlineno
        next_addr, next_lineno = linenos.pop(0)
        for x in self.nodes():
            if x.addr >= next_addr:
                current_lineno = next_lineno
                if len(linenos) != 0:
                    next_addr, next_lineno = linenos.pop(0)
            x.lineno = current_lineno

    def calc_lnotab(self):
        '''
        Creates a new co_lnotab after modifying bytecode
        '''
        rvalue = bytearray()

        prev_lineno = self.code.co_firstlineno
        prev_offset = self.head.addr

        for current in self.nodes():

            if current.lineno is None:
                # only one line of code
                continue
            if current.lineno == prev_lineno:
                continue

            rvalue.append(current.addr - prev_offset)
            rvalue.append((current.lineno - prev_lineno) & 0xff)

            prev_lineno = current.lineno
            prev_offset = current.addr
        return rvalue

    def delete_node(self, node):
        '''
        Deletes a node from the graph, removing the instruction from the
        produced bytecode stream
        '''
        if node.prev is not None and node.prev.is_extendedarg():
            self.delete_node(node.prev)

        # For each instruction pointing to instruction to be delete,
        # move the pointer to the next instruction
        for x in node.xrefs:
            x.target = node.next

            if node.next is not None:
                node.next.xrefs.append(x)

        # Clean up the doubly linked list
        if node.prev is not None:
            node.prev.next = node.next
        if node.next is not None:
            node.next.prev = node.prev
        if node == self.head:
            self.head = node.next

        del self.bytecodes[node.addr]

    def disassemble(self, start=None, count=None):
        '''
        Simple disassembly routine for analyzing nodes in the graph
        '''

        rvalue = ""
        for x in self.nodes(start):
            rvalue += "[%04d] %s\n" % (x.lineno, x.disassemble())
        return rvalue

    def get_code(self, start=None):
        '''
        Produce a new code object based on the graph
        '''
        self.refactor()

        # generate a new co_lineno
        new_co_lnotab = self.calc_lnotab()

        # generate new bytecode stream
        new_co_code = bytearray()
        for x in self.nodes(start):
            new_co_code.extend(x.bin())

        # create a new code object with modified bytecode and updated line numbers
        # a new code object is necessary because co_code is readonly
        if sys.version_info.major == 3:
            if sys.version_info.minor == 8:
                rvalue = CodeType(self.code.co_argcount,
                                self.code.co_posonlyargcount,
                                self.code.co_kwonlyargcount,
                                self.code.co_nlocals,
                                self.code.co_stacksize,
                                self.code.co_flags,
                                bytes(new_co_code),
                                self.code.co_consts,
                                self.code.co_names,
                                self.code.co_varnames,
                                self.code.co_filename,
                                self.code.co_name,
                                self.code.co_firstlineno,
                                bytes(new_co_lnotab),
                                self.code.co_freevars,
                                self.code.co_cellvars)
            else:
                rvalue = CodeType(self.code.co_argcount,
                                self.code.co_kwonlyargcount,
                                self.code.co_nlocals,
                                self.code.co_stacksize,
                                self.code.co_flags,
                                bytes(new_co_code),
                                self.code.co_consts,
                                self.code.co_names,
                                self.code.co_varnames,
                                self.code.co_filename,
                                self.code.co_name,
                                self.code.co_firstlineno,
                                bytes(new_co_lnotab),
                                self.code.co_freevars,
                                self.code.co_cellvars)
        elif sys.version_info.major == 2:
            rvalue = CodeType(self.code.co_argcount,
                            self.code.co_nlocals,
                            self.code.co_stacksize,
                            self.code.co_flags,
                            bytes(new_co_code),
                            self.code.co_consts,
                            self.code.co_names,
                            self.code.co_varnames,
                            self.code.co_filename,
                            self.code.co_name,
                            self.code.co_firstlineno,
                            bytes(new_co_lnotab))

        return rvalue

    def nodes(self, start=None):
        '''
        Iterator for stepping through bytecodes in order
        '''
        if start is None:
            current = self.head
        else:
            current = start

        while current is not None:
            try:
                yield current
                current = current.next
            except StopIteration:
                return

    def parse_bytecode(self):
        '''
        Parses the bytecode stream and creates an instruction graph
        '''

        self.bytecodes = {}
        prev = None
        offset = 0
        extended_arg = 0

        targets = []

        while offset < len(self.code.co_code):
            extended_arg *= extended_multiplier
            next = Bytecode(addr=self.base + offset,
                            buffer=self.code.co_code[offset:offset+3],
                            prev=prev)

            if next.is_extendedarg():
                extended_arg += next.oparg
                next.actualarg = extended_arg
            elif extended_arg != 0:
                next.actualarg += extended_arg
                extended_arg = 0

            self.bytecodes[self.base + offset] = next
            offset += next.len()

            if prev is not None:
                prev.next = next

            prev = next

            if next.get_target_addr() is not None:
                targets.append(next.get_target_addr())

        for x in targets:
            if x not in self.bytecodes:
                print("Nonlinear issue at offset: %08x" % x)

        self.head = self.bytecodes[self.base]
        self.apply_labels()
        return

    def patch_opargs(self, start=None):
        '''
        Updates branch instructions to correct offsets after adding or
        deleting bytecode

        Returns whether EXTENDED_ARG instructions were inserted or deleted
        '''
        modified = False

        for current in self.nodes(start):
            # No argument, skip to next
            if current.opcode < dis.HAVE_ARGUMENT:
                continue

            # Patch relative offsets
            if current.opcode in dis.hasjrel:
                current.actualarg = current.target.addr - \
                                    (current.addr+current.len())
                modified = self.clean_jump(current) or modified

            # Patch absolute offsets
            elif current.opcode in dis.hasjabs:
                current.actualarg = current.target.addr
                modified = self.clean_jump(current) or modified
        
        return modified

    def clean_jump(self, jump):
        jump.oparg = jump.actualarg % extended_multiplier
        return self.clean_extendedarg(jump, jump.actualarg // extended_multiplier)

    def clean_extendedarg(self, current, remainder):
        assert(remainder >= 0)
        if remainder == 0:
            if current.prev is not None and current.prev.is_extendedarg():
                self.delete_node(current.prev)
                return True
            else:
                return False
        else: # remainder > 0
            if current.prev is not None and current.prev.is_extendedarg():
                current.prev.oparg = remainder % extended_multiplier
                current.prev.actualarg = remainder
                return self.clean_extendedarg(current.prev, remainder // extended_multiplier)
            else: # add a extended arg node
                new_extended = Bytecode()
                new_extended.opcode = dis.opmap['EXTENDED_ARG']
                new_extended.oparg = remainder % extended_multiplier
                new_extended.actualarg = remainder
                self.add_node(current.prev, new_extended, change_target=True)
                self.clean_extendedarg(new_extended, remainder // extended_multiplier)
                return True

    def refactor(self):
        '''
        iterates through all bytecodes and determines correct offset
        position in code sequence after adding or removing bytecode
        '''
        
        modified = True
        while modified:
            offset = self.base
            new_bytecodes = {}

            for current in self.nodes():
                new_bytecodes[offset] = current
                current.addr = offset
                offset += current.len()
                current = current.next

            self.bytecodes = new_bytecodes
            modified = self.patch_opargs()
        self.apply_labels()
