from idc import *
from idautils import *
from idaapi import *

import os
import time
import sqlite3

class ConstantsMatch:
    def __init__(self, bin_name, src_name, bin_matched, src_matched, functions):
        self.bin_name = bin_name
        self.src_name = src_name
        self.bin_matched = bin_matched
        self.src_matched = src_matched
        self.functions = functions
        self.conn = None
        self.cur = None

        # self.get_sql_db()
        # self.constants_match()
        all_names = dict(Names())
        func = 0x0029D874
        res = self.constants(func, all_names)
        print res[0], res[1], res[2]
        """for func in Functions():
            res = self.constants(func, all_names)"""

    def diaphora_decode(self, ea):
        KERNEL_VERSION = get_kernel_version()
        if KERNEL_VERSION.startswith("7."):
            ins = idaapi.insn_t()
            decoded_size = idaapi.decode_insn(ins, ea)
            return decoded_size, ins
        elif KERNEL_VERSION.startswith("6."):
            decoded_size = idaapi.decode_insn(ea)
            return decoded_size, idaapi.cmd
        else:
            raise Exception("Unsupported IDA kernel version!")

    def is_constant(self, oper, ea):
        value = oper.value
        # make sure, its not a reference but really constant
        if len(list(DataRefsFrom(ea))) != 0:
            return False
        return True

    def constants(self, func, all_names):
        constants = []
        strings = []
        names = set()
        f = func
        func = get_func(func)
        flow = FlowChart(func)
        for block in flow:
            if block.endEA == 0 or block.endEA == BADADDR:
                print("0x%08x: Skipping bad basic block" % f)
                continue

            for x in list(Heads(block.startEA, block.endEA)):
                decoded_size, ins = self.diaphora_decode(x)
                i = 0
                for oper in ins.Operands:
                    i += 1
                    if oper.type == o_imm:
                        if self.is_constant(oper, x):
                            constants.append(self.constant_filter(oper.value))
                    if oper.type == o_displ:
                        if self.is_constant(oper, x):
                            value = self.constant_filter(get_operand_value(x, i-1))
                            if value != 0:
                                constants.append(value)
                    drefs = list(DataRefsFrom(x))
                    if len(drefs) > 0:
                        for dref in drefs:
                            if get_func(dref) is None:
                                str_constant = GetString(dref, -1, -1)
                                if str_constant is not None:
                                    if str_constant not in strings:
                                        strings.append(str_constant)
                op_value = GetOperandValue(x, 1)
                if op_value == -1:
                    op_value = GetOperandValue(x, 0)

                tmp_name = None
                if op_value != BADADDR and op_value in all_names:
                    tmp_name = all_names[op_value]
                    demangle_name = Demangle(tmp_name, INF_SHORT_DN)
                    if demangle_name is not None:
                        tmp_name = demangle_name
                        pos = tmp_name.find("(")
                        if pos > -1:
                            tmp_name = tmp_name[:pos]
                    
                    if not tmp_name.startswith("sub_") and not tmp_name.startswith("nullsub_"):
                        names.add(tmp_name)

        # sql = """update functions set names = ?, constants = ?
        #         where address = ?
        #    """

        # self.cur.execute(sql, [names, constants, int(f)])

        return names, constants, strings

    def get_sql_db(self):
        self.conn = sqlite3.connect(self.bin_name)
        self.cur = self.conn.cursor()
        sql = """ create table if not exists functions (
            id integer primary key,
            name varchar(255),
            address text unique,
            nodes integer,
            edges integer,
            size integer,
            instructions integer,
            mnemonics text,
            names text,
            prototype text,
            cyclomatic_complexity integer,
            primes_value text,
            comment text,
            mangled_function text,
            bytes_hash text,
            pseudocode text,
            pseudocode_lines integer,
            pseudocode_hash1 text,
            pseudocode_primes text,
            function_flags integer,
            assembly text,
            prototype2 text,
            pseudocode_hash2 text,
            pseudocode_hash3 text,
            tarjan_topological_sort text,
            clean_assembly text,
            clean_pseudo text,
            mnemonics_spp text,
            function_hash text,
            md_index text,
            constants text,
            constants_count integer,
            assembly_addrs text,
            kgh_hash text) """
        self.cur.execute(sql)
        sql = """create table if not exists results (
            bin_address text,
            bin_name varchar(255), 
            src_name varchar(255), 
            description varchar(255),
            primary key(bin_address, src_name))"""
        self.cur.execute(sql)

    def constants_match(self):
        all_names = dict(Names())
        for func in Functions(MinEA(), MaxEA()):
            constants(func, all_names, c)

        self.cur.execute('attach "%s" as diff' % self.src_name)
        self.conn.commit()

        sql = """
            select distinct f.address ea, f.name name1, df.address ea2, df.name name2,
                        'Constants and names' description
                    from functions f,
                        diff.functions df
                    where f.bytes_hash = df.bytes_hash
                    group by name1 having count(name1) == 1
            """
        # c.execute('attach "%s" as diff' % sqlite_db)
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        for row in rows:
            result.add(str(row[1]))
        print len(rows)

        print len(result)

        time_elapsed = time.time() - t0
        print('Training complete in {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

bin_matched = set()
src_matched = set()
functions = list()
constants_match = ConstantsMatch("","",bin_matched, src_matched, functions)