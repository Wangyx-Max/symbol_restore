from idautils import *
from idc import *
from idaapi import *

import json
from hashlib import md5

from sql_opt import *
from cfg_hash import CFGHash

f = open('results.txt', 'w')

class AnalyseFunction:
    def __init__(self, name):
        self.name = name
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
        if func is None:
            print("Cannot get a function object for 0x%x" % f)
            return False
        return True

    def constant_filter(self, value):
        if value < 0x100:
            return False
        if value & 0xFFFFFF00 == 0xFFFFFF00:
            return False
        if value & 0xFFFF00 == 0xFFFF00:
            return False
        if value & 0xFFFFFFFFFFFFFF00 == 0xFFFFFFFFFFFFFF00:
            return False
        if value & 0xFFFFFFFFFFFF00 == 0xFFFFFFFFFFFF00:
            return False

        return True

    def read_function(self, f):
        if self.func_check(f) is False:
            return False

        size = 0
        instructions = 0
        function_hash = []
        mnems = []
        nums = []
        nums2 = []

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

            if mnem != '' and GetOpType(line, 1) == o_displ and self.constant_filter(GetOperandValue(line, 1)):
                nums.append(GetOperandValue(line, 1))
            if mnem != '' and GetOpType(line, 2) == o_imm:
                nums.append(GetOperandValue(line, 2))
            if mnem != '' and GetOpType(line, 1) == o_imm:
                nums2.append(GetOperandValue(line, 1))

        if instructions > 5:
            nums2 = []

        function_hash = md5("".join(function_hash)).hexdigest()

        l = (name, true_name, f, flags, size, instructions,
             function_hash, mnems, nums, len(nums), nums2, len(nums2))
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
                            if str_constant not in constants and len(str_constant) > 2:
                                constants.append(str_constant)
                                # print hex(x), str_constant
                                # print hex(x), str_constant

        l = (constants, len(constants), f)
        return l

    def read_callers(self, f):
        if self.func_check(f) is False:
            return False

        callers = []
        crefs = list(CodeRefsTo(f, 0))
        if len(crefs) == 0:
            l = (callers, 0, f)
            return l

        if SegName(crefs[0]) == '.plt':
            crefs = list(CodeRefsTo(get_func(crefs[0]).startEA, 0))
        for cref in crefs:
            if SegName(cref) == '.text' and get_func(cref) is not None:
                callers.append(cref)
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

    def do_insert_function(self, l):
        """
        @ param l : name, true_name,f, flags, size, instructions, function_hash, mnems, nums, nums_count, nums2, nums2_count
        """
        props = self.create_sql_props(l)
        sql = """insert or ignore into functions (name, mangled_function, address, function_flags, size, instructions,
                    function_hash, mnemonics, numbers, numbers_count, numbers2, numbers2_count)
            values (?, ?, ?, ?, ?, ?, 
                    ?, ?, ?, ?, ?, ?)
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
            if type(constant) is str and len(constant) > 5:
                self.cur.execute(sql, (func_id, constant))
                self.conn.commit()

    def do_insert_callers(self, l):
        """
        @param l: callers, callers_count, f
        """
        (callers, callers_count, f) = l
        sql = """select id from functions where address = %s
        """
        sql_insert = """insert or ignore into callers (caller_id, caller_address, call_address, callee_address)
        values (?, ?, ?, ?)
        """
        new_callers = []
        for caller in callers:
            caller_func = get_func(int(caller)).startEA
            self.cur.execute(sql % str(caller_func))
            caller_id = self.cur.fetchone()
            if caller_id is None:
                continue
            self.cur.execute(sql_insert, (str(caller_id[0]), str(caller_func), str(caller), str(f)))
            self.conn.commit()
            new_callers.append(caller_func)
        props = self.create_sql_props((new_callers, len(new_callers), f))
        sql = """update or ignore functions set callers = ?, callers_count = ?
                where address = ?
        """
        self.cur.execute(sql, props)
        self.conn.commit()

    def save_functions(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        sql_op.create_functions()
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = self.read_function(func)
            if l is False:
                continue
            self.do_insert_function(l)
        self.cur.close()
        time_elapsed = time.time() - t0
        print('Create Functions {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def save_constants(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        sql_op.create_constants()
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = self.read_constants(func)
            if l is False:
                continue
            self.do_insert_constants(l)
        self.cur.close()
        time_elapsed = time.time() - t0
        print('Create Constants {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def update_cfg_hash(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        sql_op.create_functions()
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = self.read_cfg_hash(func)
            if l is False:
                continue
            self.do_update_cfg_hash(l)
        self.cur.close()
        time_elapsed = time.time() - t0
        print('update cfg hash {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def save_callers(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        sql_op.create_callers()
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = self.read_callers(func)
            if l is False:
                continue
            self.do_insert_callers(l)
        self.cur.close()
        time_elapsed = time.time() - t0
        print("Create Callers {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def save_code(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = self.read_callers(func)
            if l is False:
                continue
            self.do_

    def analyse_symbol(self):
        self.save_functions(self.functions)
        self.save_constants(self.functions)
        self.update_cfg_hash(self.functions)
        self.save_callers(self.functions)


class PerfectMatch:
    def __init__(self, bin_name, src_name):
        self.bin_name = bin_name
        self.src_name = src_name
        self.src_matched = set() #func_id
        self.bin_matched = set() #startEA of a function
        self.min_ea = MinEA()
        self.max_ea = MaxEA()
        self.functions = list(Functions(self.min_ea, self.max_ea))
        self.analyse_func = AnalyseFunction(self.bin_name)
        self.conn = False
        self.cur = False

    def do_insert_results(self, l):
        """
        @ param l : bin_address, bin_name, src_address, src_name, description
        """
        props = self.analyse_func.create_sql_props(l)
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
                        result_tmp[str(func.startEA)] = [string]

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
            if len(str(string)) > 5:
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
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        sum = 0
        rules_name = ['Same Name Match', 'Rare Bytes Hash Match', 'Rare Mnemonics Match', 'Rare Numbers Match']
        for rules in rules_name:
            sql = sql_dict[rules]
            sum += self.insert_results(sql)
        if self.cur is not None:
            self.cur.close()
        time_elapsed = time.time() - t0
        print('Bytes Hash Match:' + str(sum))
        print("Bytes Hash Match {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def do_constants_match(self):
        sql_opt = SqlOperate(self.bin_name)
        bin_dict = sql_opt.read_constants()
        src_dict = sql_opt.read_constants(self.src_name)
        self.conn, self.cur = sql_opt.attach(self.src_name)
        sum = 0
        for constants, funcs_id in bin_dict.items():
            if len(funcs_id) == 1 and constants in src_dict.keys():
                src_funcs_id = src_dict[constants]
                if len(src_funcs_id) != 1:
                    continue
                func_id = funcs_id[0]
                src_func_id = src_funcs_id[0]
                sql = "select address, name, size, numbers from functions where id = %d"
                self.cur.execute(sql % int(func_id))
                bin_res = self.cur.fetchone()
                sql = "select address, name, size, numbers from diff.functions where id = %d"
                self.cur.execute(sql % int(src_func_id))
                src_res = self.cur.fetchone()
                if bin_res[2] != src_res[2] or bin_res[3] != src_res[3]:
                    continue
                l = (str(bin_res[0]), str(bin_res[1]), str(src_res[0]), str(src_res[1]), 'Long Constants Match')
                self.do_insert_results(l)
                sum += 1
        if self.cur is not None:
            self.cur.close()
        return sum

    def constants_match(self):
        t0 = time.time()
        sum = 0
        sum += self.do_constants_match()

        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules_name = ['Rare Constants Match', 'Mnemonics Constants Match']
        for rules in rules_name:
            sql = sql_dict[rules]
            sum += self.insert_results(sql)
        if self.cur is not None:
            self.cur.close()
        time_elapsed = time.time() - t0
        print('Constants Match :' + str(sum))
        print('Constants Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def cfg_hash_match(self):
        t0 = time.time()
        sum = 0
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules_name = ['Rare Md_Index Match', 'Rare KOKA Hash Match', 'Md_Index Constants Match', 'Rare KOKA Hash Match']
        for rules in rules_name:
            sql = sql_dict[rules]
            sum += self.insert_results(sql)
        if self.cur is not None:
            self.cur.close()
        time_elapsed = time.time() - t0
        print("CFG Hash Match :" + str(sum))
        print("CFG Hash Match {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def do_callee_match(self):
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        rows = sql_op.read_results()
        if len(rows) == 0:
            return
        self.conn, self.cur = sql_op.attach(self.src_name)
        sql_bin = """select * from callers where caller_address = %s order by call_address
        """
        sql_src = """select * from diff.callers where caller_address = %s order by call_address
        """
        sql_func_bin = """select name, numbers, numbers_count, numbers2, numbers2_count, instructions, size from functions where address = %s
        """
        sql_func_src = """select name, numbers, numbers_count, numbers2, numbers2_count, instructions, size from diff.functions where address = %s
        """
        sum = 0
        for row in rows:
            self.cur.execute(sql_bin % row[0])
            callers = self.cur.fetchall()
            if len(callers) == 0:
                continue
            callers_bin = []
            for caller in callers:
                callers_bin.append(caller[3])
            self.cur.execute(sql_src % row[2])
            callers = self.cur.fetchall()
            if len(callers) == 0:
                continue
            callers_src = []
            for caller in callers:
                callers_src.append(caller[3])
            if len(callers_bin) == 1 and len(callers_src) == 1:
                if int(callers_bin[0]) not in self.functions:
                    continue
                self.cur.execute(sql_func_bin % callers_bin[0])
                bin = self.cur.fetchone()
                self.cur.execute(sql_func_src % callers_src[0])
                src = self.cur.fetchone()
                if bin and src and src[1] == bin[1]:
                    l = (callers_bin[0], bin[0], callers_src[0], src[0], 'Callee Match')
                    self.do_insert_results(l)
                    if int(callers_bin[0]) in self.functions:
                        self.functions.remove(int(callers_bin[0]))
                    sum += 1
            else:
                for caller_bin in callers_bin:
                    if int(caller_bin) not in self.functions:
                        continue
                    for caller_src in callers_src:
                        self.cur.execute(sql_func_bin % caller_bin)
                        bin = self.cur.fetchone()
                        self.cur.execute(sql_func_src % caller_src)
                        src = self.cur.fetchone()
                        if (src[1] == bin[1] and int(bin[2]) > 5) or\
                                (src[3] == bin[3] and int(bin[4]) > 3) or\
                                (src[1] == bin[1] and src[3] == bin[3] and src[5] == bin[5]):
                            l = (caller_bin, bin[0], caller_src, src[0], 'Callee Match')
                            self.do_insert_results(l)
                            if int(caller_bin) in self.functions:
                                self.functions.remove(int(caller_bin))
                            callers_src.remove(caller_src)
                            sum += 1
                            break

        if self.cur is not None:
            self.cur.close()
        return sum

    def do_caller_match(self):
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        rows = sql_op.read_results()
        if len(rows) == 0:
            return
        # print len(rows)
        self.conn, self.cur = sql_op.attach(self.src_name)
        sql_bin = """select callers, callers_count, name, numbers, numbers_count, numbers2, numbers2_count, instructions from functions where address = %s
        """
        sql_src = """select callers, callers_count, name, numbers, numbers_count, numbers2, numbers2_count, instructions from diff.functions where address = %s
        """
        sum = 0
        for row in rows:
            self.cur.execute(sql_bin % row[0])
            bin = self.cur.fetchone()
            self.cur.execute(sql_src % row[2])
            src = self.cur.fetchone()
            if bin and src and int(bin[1]) == 1 and int(src[1]) == 1:
                bin_addr = json.loads(str(bin[0]))[0]
                if int(bin_addr) not in self.functions:
                    continue
                src_addr = json.loads(str(src[0]))[0]
                self.cur.execute(sql_bin % bin_addr)
                bin_c = self.cur.fetchone()
                self.cur.execute(sql_src % src_addr)
                src_c = self.cur.fetchone()
                # print bin_c, src_c
                if bin_c and src_c and bin_c[3] == src_c[3]:
                    l = (bin_addr, str(bin_c[2]), src_addr, str(src_c[2]), 'Caller Match')
                    self.do_insert_results(l)
                    if int(bin_addr) in self.functions:
                        self.functions.remove(int(bin_addr))
                    sum += 1
            elif bin and src and int(bin[1]) == int(src[1]):
                bins_addr = json.loads(str(bin[0]))
                for bin_addr in bins_addr:
                    if int(bin_addr) not in self.functions:
                        continue
                    srcs_addr = json.loads(str(src[0]))
                    for src_addr in srcs_addr:
                        self.cur.execute(sql_bin % bin_addr)
                        bin_c = self.cur.fetchone()
                        self.cur.execute(sql_src % src_addr)
                        src_c = self.cur.fetchone()
                        # print bin_c, src_c
                        if bin_c and src_c and ((bin_c[3] == src_c[3] and int(bin_c[4]) > 5) or\
                                                (bin_c[5] == src_c[5] and int(bin_c[6]) > 1) or\
                                                (bin_c[3] == src_c[3] and bin_c[5] == src_c[5] and bin_c[7] == src_c[7])):
                            l = (bin_addr, str(bin_c[2]), src_addr, str(src_c[2]), 'Caller Match')
                            self.do_insert_results(l)
                            if int(bin_addr) in self.functions:
                                self.functions.remove(int(bin_addr))
                            srcs_addr.remove(src_addr)
                            sum += 1
                            break
        return sum

    def call_match(self):
        t0 = time.time()
        sum = 0
        s = self.do_callee_match()
        while s:
            sum += s
            # print s
            s = self.do_callee_match()
        s = self.do_caller_match()
        while s:
            sum += s
            s = self.do_caller_match()
        time_elapsed = time.time() - t0
        print('Call Match:' + str(sum))
        print('Call Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def do_neighbor_match(self, pairs, rule):
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
        sum = 0
        for bin_func in pairs.keys():
            if int(bin_func) not in self.functions:
                continue
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
                l = (str(bin[1]), str(bin[0]), str(src[0][2]), str(src[0][1]), rule)
                self.do_insert_results(l)
                if int(bin_func) in self.functions:
                    self.functions.remove(int(bin_func))
                    sum += 1
        return sum

    def do_constants_neighbor_match(self):
        sql_opt = SqlOperate(self.bin_name)
        bin_dict = sql_opt.read_constants()
        src_dict = sql_opt.read_constants(self.src_name)
        self.conn, self.cur = sql_opt.attach(self.src_name)
        pairs = {}
        for constants, funcs_id in bin_dict.items():
            for func_id in funcs_id:
                if constants in src_dict.keys():
                    src_funcs_id = src_dict[constants]
                    for src_func_id in src_funcs_id:
                        try:
                            pairs[func_id].append(src_func_id)
                        except:
                            pairs[func_id] = [src_func_id]
        return self.do_neighbor_match(pairs, 'Long Constants Neighbor Match')

    def neighbor_match_single(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules = ['Bytes Hash Neighbor Match', 'Mnemonics Neighbor Match', 'Constants Neighbor Match',
                 'Numbers Neighbor Match', 'MD Index Neighbor Match', 'KOKA Hash Neighbor Match']
        sum = 0
        for rule in rules:
            sql = sql_dict[rule]
            self.cur.execute(sql)
            rows = self.cur.fetchall()
            pairs = {}
            for row in rows:
                try:
                    pairs[str(row[0])].append(str(row[4]))
                except:
                    pairs[str(row[0])] = [str(row[4])]
            sum += self.do_neighbor_match(pairs, rule)
        if self.cur is not None:
            self.cur.close()

        sum += self.do_constants_neighbor_match()
        if self.cur is not None:
            self.cur.close()

        time_elapsed = time.time() - t0
        print('Neighbor Match:' + str(sum))
        print('Neighbor Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))
        return sum

    def neighbor_match(self):
        s = self.neighbor_match_single()
        while s:
            s = self.neighbor_match_single()
        print('Neighbor Match Finished')

    def do_perfect_match(self, module='match'):
        if module == 'init and match':
            self.analyse_func.save_functions(self.functions)
            # self.strings_match()
            self.bytes_hash_match()
            self.analyse_func.save_constants(self.functions)
            self.constants_match()
            self.analyse_func.update_cfg_hash(self.functions)
            self.cfg_hash_match()
            self.neighbor_match_single()
            self.analyse_func.save_callers(list(Functions(self.min_ea, self.max_ea)))
            self.call_match()
            self.neighbor_match_single()
            self.call_match()
            self.neighbor_match()

        if module == 'match':
            # self.strings_match()
            self.bytes_hash_match()
            # self.analyse_func.save_constants(self.functions)
            self.constants_match()
            # self.analyse_func.update_cfg_hash(self.functions)
            self.cfg_hash_match()
            self.neighbor_match_single()
            self.call_match()
            self.neighbor_match_single()
            self.call_match()
            self.neighbor_match()


