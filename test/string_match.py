from idc import *
from idaapi import *
from idautils import *

import json

from test.sql_opt import SqlOperate


class StrMatch(object):
    def __init__(self, bin_name, src_name):
        self.bin_name = bin_name
        self.sym_name = src_name
        self.src_matched = set()
        self.bin_matched = set()
        self.functions = Functions(MinEA(), MaxEA())
        self.has_results = False
        self.has_functions = False
        self.conn = None
        self.cur = None
        self.strings = []

    def get_sql_op(self):
        sql_op = SqlOperate(self.bin_name)
        if self.has_results is False:
            sql_op.create_results()
            self.has_results = True
        sql_op.create_constants()
        if self.has_functions is False:
            sql_op.create_functions()
            self.has_functions = True
        self.conn, self.cur = sql_op.attach(self.sym_name)

    def do_match_string(self, length, count): 
        sql = """select * from diff.constants 
            where func_id in (
                select func_id from (
                    select * from diff.constants where LENGTH(constant) > %s group by constant having count(*) == 1
                ) 
                group by func_id having count(*) == %s
            )
            and constant in (
                select constant from diff.constants where LENGTH(constant) > %s group by constant having count(*) == 1
            )
                    """

        self.cur.execute(sql%(str(length), str(count), str(length)))

        rows = self.cur.fetchall()
        print len(rows)
        sql_result = {}
        sum = 0

        for row in rows:
            print row
            sql_result[str(row[1])] = str(row[0])


        rare_strings = sql_result.keys()
        print sql_result
        result_tmp = {}
        for string in self.strings:
            if str(string) in rare_strings:
                print string
                xrefs = XrefsTo(string.ea, 0)
                for xref in xrefs:
                    func = get_func(xref.frm)
                    if func is None:
                        continue
                    try:
                        result_tmp[str(func.startEA)].append(string)
                    except:
                        result_tmp[str(func.startEA)] = [string]

        funcs_id = {}
        for key, value in result_tmp.items():
            value = list(value)
            if len(value) >= count:
                funcs_id[str(sql_result[str(value[0])])] = key 

        sql = "select name from diff.functions where id = %s"
        sql_insert = """
                insert or ignore into results (
                    bin_address, bin_name, src_name, description) 
                    values (?, ?, ?, ?)"""
        
        for func_id in set(funcs_id.keys()):
            self.cur.execute(sql % str(func_id))
            row = self.cur.fetchone()
            address = int(funcs_id[func_id])
            self.bin_matched.add(str(funcs_id[func_id]))
            self.src_matched.add(str(func_id))
            if address in self.functions:
                self.functions.remove(address)
            props = [str(address), str(GetFunctionName(address)), str(row[0]), 'String Match']
            self.cur.execute(sql_insert, props)
            self.conn.commit()
            sum += 1

        print sum
    
    def string_analyse(self):
        for string in Strings():
            if len(str(string)) > 10:
                self.strings.append(string)

        print "sum of strings(): "+str(len(self.strings))

    def read_func(self, f):
        # print "here"
        flags = GetFunctionFlags(int(f))
        if flags & FUNC_LIB or flags == -1:
            return False

        func = get_func(f)
        if not func:
            print("Cannot get a function object for 0x%x" % f)
            return False

        constants = []
        name = GetFunctionName(f)
        func = get_func(f)
        flow = FlowChart(func)
        for block in flow:
            if block.endEA == 0 or block.endEA == BADADDR:
                print("0x%08x: Skipping bad basic block" % f)
                continue
            for x in list(Heads(block.startEA, block.endEA)):
                drefs = list(DataRefsFrom(x))
                if len(drefs) > 0:
                    for dref in drefs:
                        if get_func(dref) is None:
                            str_constant = GetString(dref, -1, -1)
                            if str_constant is not None:
                                if str_constant not in constants:
                                    constants.append(str_constant)

        sql = """insert or ignore into functions (name, constants, address, function_flags) values (?, ?, ?, ?)"""
        l = (name, constants, f, flags)
        props = []
        for prop in l:
            if type(prop) is long and (prop > 0xFFFFFFFF or prop < -0xFFFFFFFF):
                prop = str(prop)
            if type(prop) is list or type(prop) is set:
                props.append(json.dumps(list(prop), ensure_ascii=False))
            else:
                props.append(prop)
        self.cur.execute(sql, props)
        self.conn.commit()
        func_id = self.cur.lastrowid
        sql = "insert into constants (func_id, constant) values (?, ?)"
        for constant in constants:
            if type(constant) is str and len(constant) > 5:
                self.cur.execute(sql, (func_id, constant))
                self.conn.commit()

    def match_string(self):
        for f in self.functions:
            self.read_func(f)
        sql = """select distinct func_id from constants 
                group by func_id having count(func_id) > 1
        """
        self.cur.execute(sql)
        bin_rows = self.cur.fetchall()
        bin_dict = {}
        sql = """select constant from constants where func_id = %s"""
        for bin_row in bin_rows:
            self.cur.execute(sql % str(bin_row[0]))
            constants = self.cur.fetchall()
            for constant in constants:
                try:
                    bin_dict[str(bin_row[0])].append(str(constant))
                except:
                    bin_dict[str(bin_row[0])] = []
                    bin_dict[str(bin_row[0])].append(str(constant))
        print bin_dict
        sql = """select distinct func_id from diff.constants 
                group by func_id having count(func_id) > 1
        """
        self.cur.execute(sql)
        src_rows = self.cur.fetchall()
        src_dict = {}
        sql = """select constant from diff.constants where func_id = %s"""
        for src_row in src_rows:
            self.cur.execute(sql % str(src_row[0]))
            constants = self.cur.fetchall()
            for constant in constants:
                try:
                    src_dict[str(src_row[0])].append(str(constant))
                except:
                    src_dict[str(src_row[0])] = []
                    src_dict[str(src_row[0])].append(str(constant))
        print src_dict
        sum = 0
        for func_id, constants in bin_dict.items():
            if constants in src_dict.values():
                src_func_id = src_dict.keys()[src_dict.values().index(constants)]
                self.print_func(func_id, src_func_id)
                # print src_func_id + '->' + func_id
                sum += 1
        print sum

    def strings_match(self):
        self.string_analyse()
        self.get_sql_op()

        parm = [(50, 1), (30, 2), (25, 3), (15, 4)]
        for length, count in parm:
            self.do_match_string(length, count)
        if self.cur is not None:
            self.cur.close()

    def print_func(self, func_id, src_func_id):
        sql = "select address from functions where id = %d"
        self.cur.execute(sql % int(func_id))
        bin_addr = self.cur.fetchone()
        sql = "select name from diff.functions where id = %d"
        self.cur.execute(sql % int(src_func_id))
        src_name = self.cur.fetchone()
        print str(src_name[0]) + "->" + str(bin_addr[0])

    def main(self):
        self.get_sql_op()
        self.strings_match()


t0 = time.time()
bin_name = "symbol_string_match.sqlite"
src_name = "C:\\Users\\Admin\\Desktop\\data6\\diff.sqlite"
sm = StrMatch(bin_name, src_name)
sm.main()
time_elapsed = time.time() - t0
print('Training complete in {:.0f}m {:.0f}s'.format(
    time_elapsed // 60, time_elapsed % 60))
