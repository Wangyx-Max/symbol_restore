import base64
from itertools import imap

from idc import *
from idaapi import *
from idautils import *
import idaapi

import os
import re
import json
from cStringIO import StringIO
from sql_opt import SqlOperate

cwd = os.getcwd()

CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]
CMP_SYMS = ["j_", "j__", " _", "__"]


def do_decompile(f):
    if IDA_SDK_VERSION >= 730:
        return decompile(f, flags=idaapi.DECOMP_NO_WAIT)
    return decompile(f)


def primesblow(N):
    # http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
    # """ Input N>=6, Returns a list of primes, 2 <= p < N """
    correction = N % 6 > 1
    N = {0: N, 1: N - 1, 2: N + 4, 3: N + 3, 4: N + 2, 5: N + 1}[N % 6]
    sieve = [True] * (N // 3)
    sieve[0] = False
    for i in range(long(N ** .5) // 3 + 1):
        if sieve[i]:
            k = (3 * i + 1) | 1
            sieve[k * k // 3::2 * k] = [False] * ((N // 6 - (k * k) // 6 - 1) // k + 1)
            sieve[(k * k + 4 * k - 2 * k * (i % 2)) // 3::2 * k] = [False] * (
                    (N // 6 - (k * k + 4 * k - 2 * k * (i % 2)) // 6 - 1) // k + 1)
    return [2, 3] + [(3 * i + 1) | 1 for i in range(1, N // 3 - correction) if sieve[i]]


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

    def get_code_hash(self, f, pseudo):
        pseudo_hash1 = None
        pseudo_hash2 = None
        pseudo_hash3 = None
        pseudocode_primes = None
        if pseudo != '':
            cfunc = do_decompile(f)
            visitor = CAstVisitor(cfunc)
            visitor.apply_to(cfunc.body, None)
            pseudocode_primes = str(visitor.primes_hash)
            kfh = CKoretFuzzyHashing()
            kfh.bsize = 32
            pseudo_hash1, pseudo_hash2, pseudo_hash3 = kfh.hash_bytes(pseudo).split(";")
            if pseudo_hash1 == "":
                pseudo_hash1 = None
            if pseudo_hash2 == "":
                pseudo_hash2 = None
            if pseudo_hash3 == "":
                pseudo_hash3 = None
        return (pseudocode_primes, pseudo_hash1, pseudo_hash2, pseudo_hash3)

    def get_mnemonics_spp(self, f):
        info = get_inf_structure()
        cpu_struct = info.procName
        if cpu_struct == 'ARM' or cpu_struct == 'ARMB':
            thumb_end_list = ['EQ', 'NE', 'CS', 'HS', 'CC', 'LO', 'MI', 'PL', 'VS',
                              'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL']
            bits_end_list = ['W', 'L', 'B', 'H']
        else:
            thumb_end_list = []
            bits_end_list = []
        func = get_func(f)
        cpu_ins_list = GetInstructionList()
        cpu_ins_list += thumb_end_list
        primes = primesblow(2048 * 2048)
        cpu_ins_list.sort()
        mnemonics_spp = 1
        for line in list(Heads(func.startEA, func.endEA)):
            mnem = GetMnem(line).split('.')[0]
            if mnem[-2:] in thumb_end_list and mnem[:-2] in cpu_ins_list:
                mnemonics_spp *= primes[cpu_ins_list.index(mnem[-2:])]
                mnem = mnem[:-2]
            if mnem[-1:] in bits_end_list and mnem[:-1] in cpu_ins_list and len(mnem) > 1:
                mnem = mnem[:-1]
            if mnem in cpu_ins_list:
                mnemonics_spp *= primes[cpu_ins_list.index(mnem)]
        return mnemonics_spp


class CAstVisitor(ctree_visitor_t):
    def __init__(self, cfunc):
        self.primes = primesblow(4096)
        ctree_visitor_t.__init__(self, CV_FAST)
        self.cfunc = cfunc
        self.primes_hash = 1
        return

    def visit_expr(self, expr):
        try:
            self.primes_hash *= self.primes[expr.op]
        except:
            traceback.print_exc()
        return 0

    def visit_insn(self, ins):
        try:
            self.primes_hash *= self.primes[ins.op]
        except:
            traceback.print_exc()
        return 0


class CKoretFuzzyHashing:
    """ Generate partial hashes of files or bytes """
    bsize = 512
    output_size = 32
    ignore_range = 2
    big_file_size = 1024 * 1024 * 10
    algorithm = None
    reduce_errors = True
    remove_spaces = False

    def get_bytes(self, f, initial, final):
        f.seek(initial)
        return f.read(final)

    def edit_distance(self, sign1, sign2):
        if sign1 == sign2:
            return 0

        m = max(len(sign1), len(sign2))
        distance = 0

        for c in xrange(0, m):
            if sign1[c:c + 1] != sign2[c:c + 1]:
                distance += 1

        return distance

    def simplified(self, bytes, aggresive=False):
        output_size = self.output_size
        bsize = self.bsize
        total_size = len(bytes)
        size = (total_size / bsize) / output_size
        buf = []
        reduce_errors = self.reduce_errors
        # Adjust the output to the desired output size
        for c in xrange(0, output_size):
            tmp = bytes[c * size:(c * size + 1) + bsize]
            ret = sum(imap(ord, tmp)) % 255
            if reduce_errors:
                if ret != 255 and ret != 0:
                    buf.append(chr(ret))
            else:
                buf.append(chr(ret))

        buf = "".join(buf)
        return base64.b64encode(buf).strip("=")[:output_size]

    def modsum(self, buf):
        return sum(imap(ord, buf)) % 255

    def _hash(self, bytes, aggresive=False):
        idx = 0
        ret = []

        output_size = self.output_size
        ignore_range = self.ignore_range
        bsize = self.bsize
        total_size = len(bytes)
        rappend = ret.append
        reduce_errors = self.reduce_errors
        # Calculate the sum of every block
        while 1:
            chunk_size = idx * bsize
            # print "pre"
            buf = bytes[chunk_size:chunk_size + bsize]
            # print "post"
            char = self.modsum(buf)

            if reduce_errors:
                if char != 255 and char != 0:
                    rappend(chr(char))
            else:
                rappend(chr(char))

            idx += 1

            if chunk_size + bsize > total_size:
                break

        ret = "".join(ret)
        size = len(ret) / output_size
        buf = []

        # Adjust the output to the desired output size
        for c in xrange(0, output_size):
            if aggresive:
                buf.append(ret[c:c + size + 1][ignore_range:ignore_range + 1])
            else:
                buf.append(ret[c:c + size + 1][1:2])

            i = 0
            for x in ret[c:c + size + 1]:
                i += 1
                if i != ignore_range:
                    continue
                i = 0
                buf += x
                break

        ret = "".join(buf)

        return base64.b64encode(ret).strip("=")[:output_size]

    def _fast_hash(self, bytes, aggresive=False):
        i = -1
        ret = set()

        output_size = self.output_size
        bsize = self.bsize
        radd = ret.add

        while i < output_size:
            i += 1
            buf = bytes[i * bsize:(i + 1) * bsize]
            char = sum(imap(ord, buf)) % 255
            if self.reduce_errors:
                if char != 255 and char != 0:
                    radd(chr(char))
            else:
                radd(chr(char))

        ret = "".join(ret)
        return base64.b64encode(ret).strip("=")[:output_size]

    def xor(self, bytes):
        ret = 0
        for byte in bytes:
            ret ^= byte
        return ret

    def _experimental_hash(self, bytes, aggresive=False):
        idx = 0
        ret = []
        bsize = self.bsize
        output_size = self.output_size
        size = len(bytes)
        chunk_size = idx * self.bsize
        byte = None

        while size > chunk_size + (bsize / output_size):
            chunk_size = idx * self.bsize
            if byte is None:
                val = bsize
            elif ord(byte) > 0:
                val = ord(byte)
            else:
                val = output_size

            buf = bytes[chunk_size:chunk_size + val]
            byte = self.xor(imap(ord, buf)) % 255
            byte = chr(byte)

            if byte != '\xff' and byte != '\x00':
                ret.append(byte)

            idx += 1

        ret = "".join(ret)
        buf = ""
        size = len(ret) / output_size
        for n in xrange(0, output_size):
            buf += ret[n * size:(n * size) + 1]

        return base64.b64encode(buf).strip("=")[:output_size]

    def mix_blocks(self, bytes):
        idx = 0
        buf = bytes
        ret = ""
        size1 = 0
        size2 = 0

        while 1:
            size1 = idx * self.bsize
            size2 = (idx + 1) * self.bsize

            tmp = buf[size1:size2]
            tm2 = tmp
            ret += tmp
            ret += tm2

            idx += 1

            if len(tmp) < self.bsize:
                break

        return ret

    def cleanSpaces(self, bytes):
        bytes = bytes.replace(" ", "").replace("\r", "").replace("\n", "")
        bytes = bytes.replace("\t", "")
        return bytes

    def hash_bytes(self, bytes, aggresive=False):
        if self.remove_spaces:
            bytes = self.cleanSpaces(bytes)

        mix = self.mix_blocks(bytes)
        if self.algorithm is None:
            func = self._hash
        else:
            func = self.algorithm

        hash1 = func(mix, aggresive)
        hash2 = func(bytes, aggresive)
        hash3 = func(bytes[::-1], aggresive)

        return hash1 + ";" + hash2 + ";" + hash3


"""
cc = CodeClean()
f = 2038624
pseudocode_lines = 0
try:
    cfunc = do_decompile(f)
    if cfunc is not None:
        pseudo = []
        sv = cfunc.get_pseudocode()
        for sline in sv:
            line = idaapi.tag_remove(sline.line)
            if line.startswith("\\"):
                continue
            pseudo.append(line)
            pseudocode_lines += 1
    pseudo = "\n".join(pseudo)
except:
    pseudo = ""
    print("Function %d can\'t be decompiled" % f)
print cc.get_code_hash(f, pseudo)
"""


