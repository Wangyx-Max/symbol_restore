"""
create functions table and store name and address
string match, same name match
update functions table with bytes hash
bytes hash match
update functions table with mnemonics and constants
mnemonics match
"""
from idautils import *
from idc import *
from idaapi import *

import json
from hashlib import md5

from sql_opt import *
from cfg_hash import CFGHash


class PerfectMatch:
    def __init__(self, bin_name, src_name = None):
        self.bin_name = bin_name
        self.src_name = src_name
        self.src_matched = set() #func_id
        self.bin_matched = set() #startEA of a function
        self.min_ea = MinEA()
        self.max_ea = MaxEA()
        self.functions = list(Functions(self.min_ea, self.max_ea))
        self.conn = False
        self.cur = False

    def func_check(self, f):
        flags = GetFunctionFlags(int(f))

        if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
            return False

        func = get_func(f)
        if not func:
            print("Cannot get a function object for 0x%x" % f)
            return False
        return True

    def read_function(self, f):
        if self.func_check(f) is False:
            return False

        size = 0
        instructions = 0
        function_hash = []
        mnems = []

        flags = GetFunctionFlags(int(f))
        func = get_func(f)
        name = GetFunctionName(int(f))
        true_name = name
        demangle_name = Demangle(name, INF_SHORT_DN)
        if demangle_name is None or demangle_name == "":
            demangle_name = None

        if demangle_name is not None:
            name = demangle_name

        for line in list(Heads(func.startEA, func.endEA)):
            mnem = GetMnem(line)
            mnems.append(mnem)
            size += ItemSize(line)
            instructions += 1
            function_hash.append(GetManyBytes(line, ItemSize(line), False))

        function_hash = md5("".join(function_hash)).hexdigest()

        l = (name, true_name, f, flags, size, instructions,
             function_hash, mnems)
        return l

    def read_cfg_hash(self, f):
        if self.func_check(f) is False:
            return False

        cfg_hash = CFGHash()
        kgh_hash, md_index, nodes = cfg_hash.md_index(f)

        l = (md_index, kgh_hash, nodes, f)
        return l

    def read_constants(self, f):
        if self.func_check(f) is False:
            return False

        func = get_func(f)
        constants = []
        for x in list(Heads(func.startEA, func.endEA)):
            drefs = list(DataRefsFrom(x))
            if len(drefs) > 0:
                for dref in drefs:
                    if get_func(dref) is None:
                        str_constant = GetString(dref, -1, -1)
                        if str_constant is not None:
                            if str_constant not in constants:
                                constants.append(str_constant)

        l = (constants, len(constants), f)
        return l

    def read_callers(self, f):
        if self.func_check(f) is False:
            return False

        callers = []
        crefs = list(CodeRefsTo(f, 0))
        if SegName(crefs[0]) == '.plt':
            crefs = list(CodeRefsTo(get_func(crefs[0]).startEA, 0))
        for cref in crefs:
            if SegName(cref) == '.text':
                callers.append(str(cref))
        l = (callers, len(callers), f)
        return l

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

    def do_insert_results(self, l):
        """
        @ param l : bin_address, bin_name, src_address, src_name, description
        """
        props = self.create_sql_props(l)
        sql_insert = """insert or ignore into results (
                    bin_address, bin_name, src_address, src_name, description) 
                    values (?, ?, ?, ?, ?)"""
        self.cur.execute(sql_insert, props)
        self.conn.commit()

    def insert_results(self, sql):
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        sum = 0
        for row in rows:
            if str(row[2]) in self.src_matched:
                continue
            self.bin_matched.add(str(row[0]))
            self.src_matched.add(str(row[2]))
            if int(str(row[0])) in self.functions:
                self.functions.remove(int(str(row[0])))
                sum += 1
            l = (str(row[0]), str(row[1]), str(row[4]), str(row[3]), str(row[5]))
            self.do_insert_results(l)
        return sum

    def do_insert_function(self, l):
        """
        @ param l : name, true_name,f, flags, size, instructions, function_hash, mnems
        """
        props = self.create_sql_props(l)
        sql = """insert or ignore into functions (name, mangled_function, address, function_flags, size, instructions,
                    function_hash, mnemonics)
            values (?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.cur.execute(sql, props)
        self.conn.commit()

    def do_update_cfg_hash(self, l):
        """
        @ param l : size, instructions, function_hash, nodes, mnemonics, f
        """
        props = self.create_sql_props(l)
        sql = """update or ignore functions set md_index = ?, kgh_hash = ?, nodes = ?
            where address = ?
            """
        self.cur.execute(sql, props)
        self.conn.commit()

    def do_insert_constants(self, l):
        """
        @ param l: constants, constants_count, f
        """
        props = self.create_sql_props(l)
        (constants, constants_count, f) = l
        sql = """update or ignore functions set constants = ?, constants_count = ? 
            where address = ?
        """
        self.cur.execute(sql, props)
        self.conn.commit()
        sql = "select id from functions where address = %d"
        # print f
        self.cur.execute(sql % int(f))
        func_id = self.cur.fetchone()
        if func_id is None:
            return
        func_id = func_id[0]
        sql = "insert or ignore into constants (func_id, constant) values (?, ?)"
        for constant in constants:
            if type(constant) is str and len(constant) > 10:
                self.cur.execute(sql, (func_id, constant))
                self.conn.commit()

    def do_insert_callers(self, l):
        """
        @param l: callers, callers_count, f
        """
        props = self.create_sql_props(l)
        (callers, callers_count, f) = l
        sql = """update or ignore functions set callers = ?, callers_count = ?
                where address = ?
        """
        self.cur.execute(sql, props)
        self.conn.commit()
        sql = """select id from functions where address = %s
        """
        sql_insert = """insert or ignore into callers (caller_id, caller_address, callee_address)
        value (?, ?, ?)
        """
        for caller in callers:
            caller_func = get_func(caller).startEA
            self.cur.execute(sql % str(caller_func))
            caller_id = self.cur.fetchone()[0]
            self.cur.execute(sql_insert, (str(caller_id), str(caller), str(f)))
            self.conn.commit()

    def save_functions(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_functions()
        self.conn, self.cur = sql_op.connect()
        for func in self.functions:
            l = self.read_function(func)
            if l is False:
                continue
            self.do_insert_function(l)
        self.cur.close()
        time_elapsed = time.time() - t0
        print('Create Functions {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def save_constants(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_constants()
        self.conn, self.cur = sql_op.connect()
        for func in self.functions:
            l = self.read_constants(func)
            if l is False:
                continue
            self.do_insert_constants(l)
        self.cur.close()
        time_elapsed = time.time() - t0
        print('Create Constants {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def save_callers(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_callers()
        self.conn = self.cur = sql_op.connect()
        for func in self.functions:
            l = self.read_callers(func)
            if l is False:
                continue
            self.do_insert_callers(l)
        self.cur.close()
        time_elapsed = time.time() - t0
        print("Create Callers {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def do_match_string(self, length, count, strings):
        sql = sql_dict['strings_match']

        self.cur.execute(sql % (str(length), str(count), str(length)))

        rows = self.cur.fetchall()

        sql_result = {}
        # sum = 0
        # print len(rows)
        for row in rows:
            try:
                sql_result[str(row[1])] = row[0]
            except:
                continue

        result_tmp = {}
        for string in strings:
            if str(string) in sql_result.keys():
                for xref in XrefsTo(string.ea, 0):
                    func = get_func(xref.frm)
                    if func is None:
                        continue
                    try:
                        result_tmp[str(func.startEA)].append(string)
                    except:
                        result_tmp[str(func.startEA)] = []
                        result_tmp[str(func.startEA)].append(string)

        funcs_id = {}
        for key, value in result_tmp.items():
            value = list(value)
            if len(value) >= count:
                funcs_id[str(sql_result[str(value[0])])] = key

        sql = "select name, address from diff.functions where id = %s"
        sum = 0
        for func_id in set(funcs_id.keys()):
            self.cur.execute(sql % str(func_id))
            row = self.cur.fetchone()
            address = int(funcs_id[func_id])
            self.bin_matched.add(str(funcs_id[func_id]))
            self.src_matched.add(str(func_id))
            if address in self.functions:
                self.functions.remove(address)
            l = (str(address), str(GetFunctionName(address)), str(row[1]), str(row[0]), 'String Match')
            self.do_insert_results(l)
            sum += 1

        return sum

    def strings_match(self):
        t0 = time.time()
        strings = []
        for string in Strings():
            if len(str(string)) > 10:
                strings.append(string)
        # print len(strings)

        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)

        parm = [(50, 1), (30, 2), (25, 3), (15, 4)]
        sum = 0
        for length, count in parm:
            sum += self.do_match_string(length, count, strings)
        if self.cur is not None:
            self.cur.close()
        time_elapsed = time.time() - t0
        print('Strings Match:' + str(sum))
        print('Strings Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def bytes_hash_match(self):
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules_name = ['Same Name Match', 'Bytes Hash Match', 'Rare Mnemonics Match']
        for rules in rules_name:
            t0 = time.time()
            sql = sql_dict[rules]
            sum = self.insert_results(sql)
            time_elapsed = time.time() - t0
            print(rules + ':' +str(sum))
            print(rules + " {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))
        if self.cur is not None:
            self.cur.close()

    def update_cfg_hash(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_functions()
        self.conn, self.cur = sql_op.connect()
        for func in self.functions:
            l = self.read_cfg_hash(func)
            if l is False:
                continue
            self.do_update_cfg_hash(l)
        self.cur.close()
        time_elapsed = time.time() - t0
        print('update cfg hash {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def do_constants_match(self):
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
        # print bin_dict
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
        # print src_dict
        sum = 0
        for func_id, constants in bin_dict.items():
            if constants in src_dict.values():
                src_func_id = src_dict.keys()[src_dict.values().index(constants)]
                sql = "select address, name from functions where id = %d"
                self.cur.execute(sql % int(func_id))
                bin_res = self.cur.fetchone()
                sql = "select address, name from diff.functions where id = %d"
                self.cur.execute(sql % int(src_func_id))
                src_res = self.cur.fetchone()
                l = (str(bin_res[0]), str(bin_res[1]), str(src_res[0]), str(src_res[1]), 'Constants Match')
                self.do_insert_results(l)
                sum += 1
        return sum

    def constants_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        sum = self.do_constants_match()
        time_elapsed = time.time() - t0
        print('Constants Match:' + str(sum))
        print('Constants Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))
        rules_name = ['Rare Constants Match', 'Mnemonics Constants match']
        for rules in rules_name:
            t0 = time.time()
            sql = sql_dict[rules]
            sum = self.insert_results(sql)
            time_elapsed = time.time() - t0
            print(rules + ":" +str(sum))
            print(rules + " {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))
        if self.cur is not None:
            self.cur.close()

    def cfg_hash_match(self):
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules_name = ['Rare Md_Index Match', 'Rare KOKA Hash Match', 'Md_Index Constants Match', 'KOKA Hash Constants Match']
        for rules in rules_name:
            t0 = time.time()
            sql = sql_dict[rules]
            sum = self.insert_results(sql)
            time_elapsed = time.time() - t0
            print(rules + ":" +str(sum))
            print(rules + " {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))
        if self.cur is not None:
            self.cur.close()

    def caller_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        sql = sql_dict['neighbor_match']
        sql_bin = """select id from functions where bin_address = %s
        """
        sql_callers = """select * from callers where caller_id = %s
        """
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        for row in rows:
            self.cur.execute(sql_bin % str(row[0]))
            caller_id = self.cur.fetchone()[0]
            self.cur.execute(sql_callers % str(caller_id))
            callers = self.cur.fetchall()
            callers_bin = []
            for caller in callers:
                callers_bin.append(caller)


    def neighbor_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        sql = sql_dict['neighbor_match']
        sql_results = """select * from results where bin_address = %s
        """
        sql_pre = """select address from functions where address < %s
                    order by address desc    
        """
        sql_bck = """select address from functions where address > %s
                    order by address
        """
        sql_bin = """select name, address from functions where address = %s
                """
        sql_src = """select id, name, address from diff.functions where address > %s and address < %s
        """

        self.cur.execute(sql)
        rows = self.cur.fetchall()
        sum = 0
        pairs = {}
        for row in rows:
            try:
                pairs[str(row[0])].append(str(row[4]))
            except:
                pairs[str(row[0])] = []
                pairs[str(row[0])].append(str(row[4]))
        for bin_func in pairs.keys():
            self.cur.execute(sql_pre % bin_func)
            one = self.cur.fetchone()
            if one is None:
                continue
            self.cur.execute(sql_results % str(one[0]))
            pre = self.cur.fetchall()
            if len(pre) != 1:
                continue
            self.cur.execute(sql_bck % bin_func)
            one = self.cur.fetchone()
            if one is None:
                continue
            self.cur.execute(sql_results % str(one[0]))
            bck = self.cur.fetchall()
            if len(bck) != 1:
                continue
            self.cur.execute(sql_src % (str(pre[0][2]), str(bck[0][2])))
            src = self.cur.fetchall()
            if len(src) != 1:
                continue
            if str(src[0][2]) in pairs[bin_func]:
                self.cur.execute(sql_bin % bin_func)
                bin = self.cur.fetchone()
                l = (str(bin[1]), str(bin[0]), str(src[0][2]), str(src[0][1]), 'Neighbor Match')
                self.do_insert_results(l)
                sum += 1

        if self.cur is not None:
            self.cur.close()
        time_elapsed = time.time() - t0
        print('Neighbor Match:' + str(sum))
        print('Neighbor Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def do_perfect_match(self):
        self.save_functions()
        self.strings_match()
        self.bytes_hash_match()
        self.save_constants()
        self.constants_match()
        self.update_cfg_hash()
        self.cfg_hash_match()
        self.neighbor_match()
        self.neighbor_match()
        self.save_callers()


    def do_test_string_match(self):
        self.strings_match()

    def analyse_symbol(self):
        self.save_functions()
        self.save_constants()
        self.update_cfg_hash()
