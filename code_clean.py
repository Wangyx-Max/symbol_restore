from idc import *
from idaapi import *
from idautils import *

import os
import re
import json
from cStringIO import StringIO
from sql_opt import SqlOperate

cwd = os.getcwd()
f = open(cwd + "result.txt","w")

CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]
CMP_SYMS = ["j_", "j__", " _", "__"]


class CodeClean:
    def __init__(self):
        self.re_cache = {}

    def re_sub(self, text, repl, string):
        if text not in self.re_cache:
            self.re_cache[text] = re.compile(text, flags=re.IGNORECASE)

        re_obj = self.re_cache[text]
        return re_obj.sub(repl, string)

    def get_cmp_asm(self, asm):
        if asm is None:
            return asm

        # Ignore the comments in the assembly dump
        tmp = asm.split(";")[0]
        tmp = tmp.split(" # ")[0]
        # Now, replace sub_, byte_, word_, dword_, loc_, etc...
        for rep in CMP_REPS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", "XXXX", tmp)

        # Remove dword ptr, byte ptr, etc...
        for rep in CMP_REMS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", "", tmp)

        for rep in CMP_SYMS:
            tmp = self.re_sub(rep + "[a-zA-Z][a-z0-9A-Z_]+", "XXXX", tmp)

        if "=(" in tmp:
            tmp = tmp.split("=(")[0] + "XXXX"

        reps = ["\+[a-f0-9A-F]+h\+"]
        for rep in reps:
            tmp = self.re_sub(rep, "+XXXX+", tmp)
        tmp = self.re_sub("\.\.[a-f0-9A-F]{8}", "XXX", tmp)

        # Strip any possible remaining white-space character at the end of
        # the cleaned-up instruction
        tmp = self.re_sub("[ \t\n]+$", "", tmp)

        # Replace aName_XXX with aXXX, useful to ignore small changes in
        # offsets created to strings
        tmp = self.re_sub("a[A-Z]+[a-z0-9]+_[0-9]+", "aXXX", tmp)
        return tmp

    def get_cmp_asm_lines(self, asm):
        sio = StringIO(asm)
        lines = []
        for line in sio.readlines():
            line = line.strip("\n")
            lines.append(self.get_cmp_asm(line))
        return "\n".join(lines)

    def get_cmp_pseudo_lines(self, pseudo):
        if pseudo is None:
            return pseudo

        # Remove all the comments
        tmp = self.re_sub(" // .*", "", pseudo)

        # Now, replace sub_, byte_, word_, dword_, loc_, etc...
        for rep in CMP_REPS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", rep + "XXXX", tmp)
        tmp = self.re_sub("v[0-9]+", "vXXX", tmp)
        tmp = self.re_sub("a[0-9]+", "aXXX", tmp)
        tmp = self.re_sub("arg_[0-9]+", "aXXX", tmp)
        return tmp

    def func_check(self, f):
        flags = GetFunctionFlags(int(f))

        if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
            return False

        func = get_func(f)
        if not func:
            print("Cannot get a function object for 0x%x" % f)
            return False
        return True

    def create_sql_props(self, l):
        props = []
        for prop in l:
            if type(prop) is long and (prop > 0xFFFFFFFF or prop < -0xFFFFFFFF):
                prop = str(prop)
            if type(prop) is list or type(prop) is set:
                props.append(json.dumps(list(prop), ensure_ascii=False))
            else:
                props.append(prop)
        return props

    def main(self):
        t0 = time.time()
        sql = """insert or ignore into functions (assembly, clean_assembly, pseudocode, clean_pseudo, address) 
              values (?, ?, ?, ?, ?)"""
        name = "code_match.sqlite"
        sql_opt = SqlOperate(name)
        sql_opt.create_functions()
        conn, cur = sql_opt.connect()
        for f in list(Functions(MinEA(), MaxEA())):
            if self.func_check(f) is False:
                continue
            func = get_func(f)
            asm = []
            for x in list(Heads(func.startEA, func.endEA)):
                tmp = idc.Get
                asm.append(GetDisasm(x))

            asm = "\n".join(asm)
            clean_asm = self.get_cmp_asm_lines(asm)
            cfunc = decompile(f, flags = idaapi.DECOMP_NO_WAIT)
            if cfunc is not None:
                pseudo = []
                sv = cfunc.get_pseudocode()
                for sline in sv:
                    line = tag_remove(sline.line)
                    if line.startswith("\\"):
                        continue
                    pseudo.append(line)
            pseudo = "\n".join(pseudo)
            clean_pseudo = self.get_cmp_pseudo_lines(pseudo)
            l = (asm, clean_asm, pseudo, clean_pseudo, f)
            props = self.create_sql_props(l)
            cur.execute(sql, props)
            conn.commit()
        cur.close()
        time_elapsed = time.time() - t0
        print('Same Name Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))


cc = CodeClean()
cc.main()
"""
import os
from cStringIO import StringIO
import re

CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
            "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
            "stru_", "dbl_", "locret_"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]
CMP_SYMS = ["j__", " _", "__"]
re_cache = {}

def re_sub(text, repl, string):
    if text not in re_cache:
        re_cache[text] = re.compile(text, flags=re.IGNORECASE)

    re_obj = re_cache[text]
    return re_obj.sub(repl, string)


def get_cmp_asm(asm):
    if asm is None:
        return asm

    # Ignore the comments in the assembly dump
    tmp = asm.split(";")[0]
    tmp = tmp.split(" # ")[0]
    # Now, replace sub_, byte_, word_, dword_, loc_, etc...
    for rep in CMP_REPS:
        tmp = re_sub(rep + "[a-f0-9A-F]+", "XXXX", tmp)

    # Remove dword ptr, byte ptr, etc...
    for rep in CMP_REMS:
        tmp = re_sub(rep + "[a-f0-9A-F]+", "", tmp)

    for rep in CMP_SYMS:
        tmp = re_sub(rep + "[a-zA-Z][a-z0-9A-Z_]+", "XXXX", tmp)

    tmp = re_sub("=\([a-z0-9A-Z_]+", "XXXX", tmp)

    reps = ["\+[a-f0-9A-F]+h\+"]
    for rep in reps:
        tmp = re_sub(rep, "+XXXX+", tmp)
    tmp = re_sub("\.\.[a-f0-9A-F]{8}", "XXX", tmp)

    # Strip any possible remaining white-space character at the end of
    # the cleaned-up instruction
    tmp = re_sub("[ \t\n]+$", "", tmp)

    # Replace aName_XXX with aXXX, useful to ignore small changes in 
    # offsets created to strings
    tmp = re_sub("a[A-Z]+[a-z0-9]+_[0-9]+", "aXXX", tmp)
    return tmp


def get_cmp_asm_lines(asm):
    sio = StringIO(asm)
    lines = []
    for line in sio.readlines():
        line = line.strip("\n")
        lines.append(get_cmp_asm(line))
    return "\n".join(lines)


asm = "
CMP.W          __n, #0x10000000
ITT CC
LSLCC           this, __n, #4
BCC.W           j_j__Znwj
PUSH            {R7,LR}
MOV             R7, SP
LDR             R0, =(_aAllocatorTAllo - 0x2A7BE6)
ADD             R0, PC
BL              _ZNSt6__ndk120__throw_length_errorEPKc
"
clean_assembly = get_cmp_asm_lines(asm)
print clean_assembly

"""



