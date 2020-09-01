from idautils import *
from idc import *
from idaapi import *
import idaapi

from hashlib import md5
from difflib import SequenceMatcher

from utils import *


def do_decompile(f):
    if IDA_SDK_VERSION >= 730:
        return decompile(f, flags=idaapi.DECOMP_NO_WAIT)
    return decompile(f)


def func_check(f):
    flags = GetFunctionFlags(int(f))

    if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
        return False

    func = get_func(f)
    if func is None:
        print("Cannot get a function object for 0x%x" % f)
        return False
    return True


def constant_filter(value):
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


def read_function(f):
    """
    @param f: the start address of a function
    @return l:
        name, mangled_function, name_hash, mangled_hash, address, function_flags, size,
        instructions, bytes_hash, mnemonics, numbers, numbers_count, numbers2, numbers2_count
    """
    if func_check(f) is False:
        return False

    size = 0
    instructions = 0
    bytes_hash = []
    mnems = []
    nums = []
    nums2 = []

    flags = GetFunctionFlags(int(f))
    func = get_func(f)
    name = GetFunctionName(int(f))
    true_name = name
    mangled_name = Demangle(name, INF_SHORT_DN)
    if mangled_name is None or mangled_name == "":
        mangled_name = None

    if mangled_name is not None:
        name = mangled_name

    if name.startswith('sub_') or name.startswith('nullsub_'):
        name_hash = None
    else:
        name_hash = md5(name).hexdigest()
    true_name_hash = None
    if mangled_name is not None:
        true_name_hash = md5(mangled_name).hexdigest()

    for line in list(Heads(func.startEA, func.endEA)):
        mnem = GetMnem(line)
        mnems.append(mnem)
        size += ItemSize(line)
        instructions += 1
        bytes_hash.append(GetManyBytes(line, ItemSize(line), False))

        if mnem != '' and GetOpType(line, 1) == o_displ and constant_filter(GetOperandValue(line, 1)):
            nums.append(GetOperandValue(line, 1))
        if mnem != '' and GetOpType(line, 2) == o_imm:
            nums.append(GetOperandValue(line, 2))
        if mnem != '' and GetOpType(line, 1) == o_imm:
            nums2.append(GetOperandValue(line, 1))

    if instructions > 5:
        nums2 = []

    bytes_hash = md5("".join(bytes_hash)).hexdigest()

    l = (name, true_name, name_hash, true_name_hash, f, flags, size, instructions,
         bytes_hash, mnems, nums, len(nums), nums2, len(nums2))
    return l


def read_cfg_hash(f):
    """
    @param f: the start address of a function
    @return l:
        md_index, kgh_hash, nodes, address
    """
    if func_check(f) is False:
        return False

    kgh_hash, md_index, nodes = cfg_hash(f)

    l = (md_index, kgh_hash, nodes, f)
    return l


def read_constants(f):
    """
    @param f: the start address of a function
    @return l:
        constants, constants_count, address
    """
    if func_check(f) is False:
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
                            # print hex(x), str_constant
                            # print hex(x), str_constant

    l = (constants, len(constants), f)
    return l


def read_callers(f):
    """
    @param f: the start address of a function
    @return l:
        callers, callers_count, address
    """
    if func_check(f) is False:
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


def read_code_show(f):
    """
    @param f: the start address of a function
    @return l:
        assembly, pseudocode, pseudocode_lines, address
    """
    if func_check(f) is False:
        return False
    func = get_func(f)
    asm = []
    pseudocode_lines = 0
    for x in list(Heads(func.startEA, func.endEA)):
        asm.append(GetDisasm(x))

    asm = "\n".join(asm)
    try:
        cfunc = do_decompile(f)
        if cfunc is not None:
            pseudo = []
            sv = cfunc.get_pseudocode()
            for sline in sv:
                line = tag_remove(sline.line)
                if line.startswith("\\"):
                    continue
                pseudo.append(line)
                pseudocode_lines += 1
        pseudo = "\n".join(pseudo)
    except:
        pseudo = ""
        print("Function %d can\'t be decompiled" % f)
    return (asm, pseudo, pseudocode_lines, f)


def read_code(f):
    """
    @param f: the start address of a function
    @return l:
        assembly, clean_assembly, pseudocode, clean_pseudo, pseudocode_lines,
        mnemonics_spp, pseudocode_primes, pseudo_hash1, pseudo_hash2, pseudo_hash3, address
    """
    if func_check(f) is False:
        return False
    func = get_func(f)
    asm = []
    cc = CodeClean()
    pseudocode_lines = 0
    cpu_ins_list = GetInstructionList()
    primes = primesblow(2048 * 2048)
    cpu_ins_list.sort()
    mnemonics_spp = 1
    for x in list(Heads(func.startEA, func.endEA)):
        asm.append(GetDisasm(x))
        mnem = GetMnem(x).split('.')[0]
        if mnem in cpu_ins_list:
            mnemonics_spp *= primes[cpu_ins_list.index(mnem)]

    asm = "\n".join(asm)
    asm_clean = cc.get_cmp_asm_lines(asm)
    try:
        cfunc = do_decompile(f)
        if cfunc is not None:
            pseudo = []
            sv = cfunc.get_pseudocode()
            for sline in sv:
                line = tag_remove(sline.line)
                if line.startswith("\\"):
                    continue
                pseudo.append(line)
                pseudocode_lines += 1
        pseudo = "\n".join(pseudo)
    except:
        pseudo = ""
        print("Function %d can\'t be decompiled" % f)
    pseudo_clean = cc.get_cmp_pseudo_lines(pseudo)
    ch = CodeClean()
    (pseudocode_primes, pseudo_hash1, pseudo_hash2, pseudo_hash3) \
        = ch.get_code_hash(f, pseudo)
    l = (asm, asm_clean, pseudo, pseudo_clean, pseudocode_lines,
         mnemonics_spp, pseudocode_primes, pseudo_hash1, pseudo_hash2, pseudo_hash3, f)
    return l


class AnalyseFunction:
    def __init__(self, name):
        self.name = name
        self.min_ea = MinEA()
        self.max_ea = MaxEA()
        self.functions = list(Functions(self.min_ea, self.max_ea))
        self.conn = False
        self.cur = False

    def do_insert_function(self, l):
        """
        @ param l : name, true_name, name_hash, mangled_hash, f, flags, size, instructions,
        bytes_hash, mnems, nums, nums_count, nums2, nums2_count
        """
        props = create_sql_props(l)
        sql = """insert or ignore into functions (name, mangled_function, name_hash, mangled_hash, address, function_flags, size, instructions,
                    bytes_hash, mnemonics, numbers, numbers_count, numbers2, numbers2_count)
            values (?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?)
        """
        self.cur.execute(sql, props)
        self.conn.commit()

    def do_update_cfg_hash(self, l):
        """
        @ param l : md_index, kgh_hash, nodes, f
        """
        props = create_sql_props(l)
        sql = """update or ignore functions set md_index = ?, kgh_hash = ?, nodes = ?
            where address = ?
            """
        self.cur.execute(sql, props)
        self.conn.commit()

    def do_insert_constants(self, l):
        """
        @ param l: constants, constants_count, f
        """
        props = create_sql_props(l)
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
        props = create_sql_props((new_callers, len(new_callers), f))
        sql = """update or ignore functions set callers = ?, callers_count = ?
                where address = ?
        """
        self.cur.execute(sql, props)
        self.conn.commit()

    def do_update_code(self, l):
        """
        @param l: assembly, clean_assembly, pseudocode, clean_pseudo, pseudocode_lines,
         mnemonics_spp, pseudocode_primes, pseudocode_hash1, pseudocode_hash2, pseudocode_hash3, f
        """
        props = create_sql_props(l)
        sql = """update or ignore functions 
        set assembly = ?, clean_assembly = ?, pseudocode = ?, clean_pseudo = ?, pseudocode_lines = ?,
        mnemonics_spp = ?, pseudocode_primes = ?, pseudocode_hash1 = ?, pseudocode_hash2 = ?, pseudocode_hash3 = ?
        where address = ?
        """
        self.cur.execute(sql, props)
        self.conn.commit()

    def do_update_code_show(self, l):
        """
        @param l: assembly, pseudocode, f
        """
        props = create_sql_props(l)
        sql = """update or ignore functions
        set assembly = ?, pseudocode = ? where address = ?
        """
        self.cur.execute(sql, props)
        self.conn.commit()

    def save_functions(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        sql_op.create_functions()
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = read_function(func)
            if l is False:
                continue
            self.do_insert_function(l)
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print('Create Functions {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def save_constants(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        sql_op.create_constants()
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = read_constants(func)
            if l is False:
                continue
            self.do_insert_constants(l)
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print('Create Constants {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def update_cfg_hash(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        sql_op.create_functions()
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = read_cfg_hash(func)
            if l is False:
                continue
            self.do_update_cfg_hash(l)
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print('Update cfg hash {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def save_callers(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        sql_op.create_callers()
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = read_callers(func)
            if l is False:
                continue
            self.do_insert_callers(l)
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print("Create Callers {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def update_code(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = read_code(func)
            if l is False:
                continue
            self.do_update_code(l)
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print("Update code {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def update_code_show(self, functions):
        t0 = time.time()
        sql_op = SqlOperate(self.name)
        self.conn, self.cur = sql_op.connect()
        for func in functions:
            l = read_code_show(func)
            if l is False:
                continue
            self.do_update_code_show(l)
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print("Update code {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def analyse_symbol_slow(self):
        self.save_functions(self.functions)
        self.save_callers(self.functions)
        self.save_constants(self.functions)
        self.update_cfg_hash(self.functions)
        self.update_code(self.functions)

    def analyse_symbol(self):
        self.save_functions(self.functions)
        self.save_callers(self.functions)
        self.save_constants(self.functions)
        self.update_cfg_hash(self.functions)
        self.update_code_show(self.functions)


class Match:
    def __init__(self, bin_name, src_name):
        """
        define member variables
        @param
            bin_name: the name of no symbol program
            src_name: the name of symbol program
        """
        self.bin_name = bin_name
        self.src_name = src_name
        self.conn = False
        self.cur = False
        self.min_ea = MinEA()
        self.max_ea = MaxEA()
        self.functions = list(Functions(self.min_ea, self.max_ea))
        self.src_matched = set()  # startEA of a function

    def do_insert_results(self, l, rename='results'):
        """
        @ param l : recording of a result
            rename : name of inserted table
        """
        props = create_sql_props(l)
        if rename == 'results' or rename.endswith('code_hash'):
            sql_insert = """insert into results (
                    bin_address, bin_name, src_address, src_name, description) 
                    values (?, ?, ?, ?, ?)"""
        elif rename == 'results_multi':
            sql_insert = """insert into results_multi (
                                bin_address, bin_name, src_address, src_name, description) 
                                values (?, ?, ?, ?, ?)"""
        else:
            sql_insert = """insert into results_fuzzy (
                                bin_address, bin_name, src_address, src_name, ratio, description) 
                                values (?, ?, ?, ?, ?, ?)"""
        try:
            self.cur.execute(sql_insert, props)
            self.conn.commit()
            if int(l[0]) in self.functions:
                self.functions.remove(int(l[0]))
            self.src_matched.add(int(l[2]))
            return 1
        except:
            return 0

    def insert_results(self, sql, rename='results'):
        """
        get matched functions and insert into tables
        @param sql : match functions sql
            rename : name of inserted table
        """
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        res = 0
        for row in rows:
            l = (str(row[0]), str(row[1]), str(row[4]), str(row[3]), str(row[5]))
            if rename.startswith('results_fuzzy'):
                r = check_ratio(str(row[8]), str(row[9]),
                                str(row[6]), str(row[7]),
                                str(row[10]), str(row[11]),
                                str(row[12]), str(row[13]))
                # r = make_score(row, self.cur)
                if rename.endswith('code_hash') and r == 1:
                    l = (str(row[0]), str(row[1]), str(row[4]), str(row[3]), str(row[5]))
                elif r > 0.99:
                    l = (str(row[0]), str(row[1]), str(row[4]), str(row[3]), r, str(row[5]))
                else:
                    continue
            res += self.do_insert_results(l, rename)
        return res

    def update_match_results(self):
        """
        update variable functions and src_matched
        """
        sql_op = SqlOperate(self.bin_name)
        rows = sql_op.read_results()
        sum = 0
        for row in rows:
            if int(row[0]) in self.functions:
                self.functions.remove(int(row[0]))
                sum += 1
            self.src_matched.add(int(row[2]))
        rows = sql_op.read_results_multi()
        for row in rows:
            if int(row[0]) in self.functions:
                self.functions.remove(int(row[0]))
                sum += 1
            self.src_matched.add(int(row[2]))
        rows = sql_op.read_results_fuzzy()
        for row in rows:
            if int(row[0]) in self.functions:
                self.functions.remove(int(row[1]))
                sum += 1
            self.src_matched.add(int(row[3]))
        return sum


class PerfectMatch(Match):
    def __init__(self, bin_name, src_name):
        Match.__init__(self, bin_name, src_name)
        self.af = AnalyseFunction(self.bin_name)

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
        res = 0
        for func_id in set(funcs_id.keys()):
            self.cur.execute(sql % str(func_id))
            row = self.cur.fetchone()
            address = int(funcs_id[func_id])
            l = (str(address), str(GetFunctionName(address)), str(row[1]), str(row[0]), 'String Match')
            res += self.do_insert_results(l)
        return res

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
        res = 0
        parm = [(50, 1), (30, 2), (25, 3), (15, 4)]
        for length, count in parm:
            res = self.do_match_string(length, count, strings)
        if self.cur is not None:
            self.cur.close()
            self.conn.close()
        time_elapsed = time.time() - t0
        print('Strings Match:' + str(res))
        print('Strings Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))

    def bytes_hash_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules_name = ['Same Name Match', 'Rare Bytes Hash Match', 'Rare Mnemonics Match']
        res = 0
        for rules in rules_name:
            sql = sql_dict[rules]
            res += self.insert_results(sql)
        if self.cur is not None:
            self.cur.close()
            self.conn.close()
        time_elapsed = time.time() - t0
        print('Basic Information Match:' + str(res))
        print("Basic Information Match {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))
        if res != 0:
            self.call_match()

    def do_constants_match(self):
        sql_opt = SqlOperate(self.bin_name)
        bin_dict = sql_opt.read_constants()
        src_dict = sql_opt.read_constants(self.src_name)
        self.conn, self.cur = sql_opt.attach(self.src_name)
        res = 0
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
                res += self.do_insert_results(l)
        if self.cur is not None:
            self.cur.close()
            self.conn.close()
        return res

    def constants_match(self):
        t0 = time.time()
        self.do_constants_match()

        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules_name = ['Rare Constants Match', 'Mnemonics Constants Match']
        res = 0
        for rules in rules_name:
            sql = sql_dict[rules]
            res += self.insert_results(sql)
        if self.cur is not None:
            self.cur.close()
            self.conn.close()
        time_elapsed = time.time() - t0
        print('Constants Match:' + str(res))
        print('Constants Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))
        if res != 0:
            self.call_match()

    def cfg_hash_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules_name = ['Rare Md_Index Match', 'Rare KOKA Hash Match', 'Md_Index Constants Match', 'Rare KOKA Hash Match']
        res = 0
        for rules in rules_name:
            sql = sql_dict[rules]
            res += self.insert_results(sql)
        if self.cur is not None:
            self.cur.close()
            self.conn.close()
        time_elapsed = time.time() - t0
        print("CFG Hash Match :" + str(res))
        print("CFG Hash Match {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))
        if res != 0:
            self.call_match()

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
        sql_func_bin = """select name, numbers, numbers_count, numbers2, numbers2_count, instructions, bytes_hash from functions where address = %s
        """
        sql_func_src = """select name, numbers, numbers_count, numbers2, numbers2_count, instructions, bytes_hash from diff.functions where address = %s
        """
        res = 0
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
                    l = (callers_bin[0], bin[0], callers_src[0], src[0], 'Single Callee Match')
                    res += self.do_insert_results(l)
            else:
                for caller_bin in callers_bin:
                    if int(caller_bin) not in self.functions:
                        continue
                    for caller_src in callers_src:
                        self.cur.execute(sql_func_bin % caller_bin)
                        bin = self.cur.fetchone()
                        self.cur.execute(sql_func_src % caller_src)
                        src = self.cur.fetchone()
                        if (src[1] == bin[1] and int(bin[2]) > 5) or \
                                (src[3] == bin[3] and int(bin[4]) > 3) or \
                                (src[1] == bin[1] and src[3] == bin[3] and src[5] == bin[5]):
                            l = (caller_bin, bin[0], caller_src, src[0], 'Callee Match')
                            res += self.do_insert_results(l)
                            callers_src.remove(caller_src)
                            break
        if self.cur is not None:
            self.cur.close()
            self.conn.close()
        return res

    def do_caller_match(self):
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        rows = sql_op.read_results()
        if len(rows) == 0:
            return
        self.conn, self.cur = sql_op.attach(self.src_name)
        sql_bin = """select callers, callers_count, name, numbers, numbers_count, bytes_hash, mnemonics, numbers2 from functions where address = %s
        """
        sql_src = """select callers, callers_count, name, numbers, numbers_count, bytes_hash, mnemonics, numbers2 from diff.functions where address = %s
        """
        res = 0
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
                    l = (bin_addr, str(bin_c[2]), src_addr, str(src_c[2]), 'Single Caller Match')
                    res += self.do_insert_results(l)
            elif bin[1] == src[1]:
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
                        if bin_c and src_c and (bin_c[5] == src_c[5] or
                                                (bin_c[6] == src_c[6] and bin_c[7] == src_c[7]) or
                                                (bin_c[3] == src_c[3] and int(bin_c[4]) > 5)):
                            l = (bin_addr, str(bin_c[2]), src_addr, str(src_c[2]), 'Caller Match')
                            res += self.do_insert_results(l)
                            srcs_addr.remove(src_addr)
                            break
        if self.cur is not None:
            self.cur.close()
            self.conn.close()
        return res

    def call_match(self):
        t0 = time.time()
        res = 0
        while True:
            s = self.do_callee_match() + self.do_caller_match()
            res += s
            if s == 0:
                break
        time_elapsed = time.time() - t0
        print('Call Match:' + str(res))
        print('Call Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))
        return res

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
        sql_src_pre = """select id, name, address from diff.functions where address > %s order by address
                            """
        sql_src_bck = """select id, name, address from diff.functions where address < %s order by address desc
                            """
        res = 0
        for bin_func in pairs.keys():
            if int(bin_func) not in self.functions:
                continue
            self.cur.execute(sql_pre % bin_func)
            one_p = self.cur.fetchone()
            self.cur.execute(sql_bck % bin_func)
            one_b = self.cur.fetchone()
            pre = None
            bck = None
            if one_p:
                self.cur.execute(sql_results % str(one_p[0]))
                pre = self.cur.fetchall()
            if one_b:
                self.cur.execute(sql_results % str(one_b[0]))
                bck = self.cur.fetchall()
            if pre and bck:
                self.cur.execute(sql_src % (str(pre[0][2]), str(bck[0][2])))
                srcs = self.cur.fetchall()
                if len(srcs) == 0:
                    continue
                for src in srcs:
                    if str(src[2]) in pairs[bin_func]:
                        self.cur.execute(sql_bin % bin_func)
                        bin = self.cur.fetchone()
                        l = (str(bin[1]), str(bin[0]), str(src[2]), str(src[1]), rule + ' (bilateral)')
                        res += self.do_insert_results(l)
                        break
            elif pre:
                self.cur.execute(sql_src_pre % str(pre[0][2]))
                src = self.cur.fetchone()
                if src and str(src[2]) in pairs[bin_func]:
                    self.cur.execute(sql_bin % bin_func)
                    bin = self.cur.fetchone()
                    l = (str(bin[1]), str(bin[0]), str(src[2]), str(src[1]), rule + ' (unilateral pre)')
                    res += self.do_insert_results(l)
                    continue
            elif bck:
                self.cur.execute(sql_src_bck % str(bck[0][2]))
                src = self.cur.fetchone()
                if src and str(src[2]) in pairs[bin_func]:
                    self.cur.execute(sql_bin % bin_func)
                    bin = self.cur.fetchone()
                    l = (str(bin[1]), str(bin[0]), str(src[2]), str(src[1]), rule + ' (unilateral back)')
                    res += self.do_insert_results(l)
        return res

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
        res = self.do_neighbor_match(pairs, 'Long Constants Neighbor Match')
        self.cur.close()
        self.conn.close()
        return res

    def neighbor_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules = ['Bytes Hash Neighbor Match', 'Mnemonics Neighbor Match', 'Constants Neighbor Match',
                 'MD Index Neighbor Match', 'KOKA Hash Neighbor Match', 'Assembly Neighbor Match',
                 'Clean Assembly Neighbor Match', 'Pseudocode Neighbor Match', 'Clean Pseudocode Neighbor Match']
        res = 0
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
            res += self.do_neighbor_match(pairs, rule)
        if self.cur is not None:
            self.cur.close()
            self.conn.close()

        res += self.do_constants_neighbor_match()

        time_elapsed = time.time() - t0
        print('Neighbor Match:' + str(res))
        print('Neighbor Match {:.0f}m {:.0f}s'.format(time_elapsed // 60, time_elapsed % 60))
        if res != 0:
            res += self.call_match()
        return res

    def code_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules = ['Rare Pseudocode Match', 'Rare Assembly Match',
                 'Rare Clean Pseudocode Match', 'Rare Clean Assembly Match']
        res = 0
        for rule in rules:
            sql = sql_dict[rule]
            res += self.insert_results(sql)
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print('Code Match:' + str(res))
        print("Code Match {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))
        if res != 0:
            self.call_match()

    def code_hash_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules = ['Rare Mnemonics Spp Match', 'Rare Pseudocode Fuzzy Hash Match(Mixed)',
                 'Rare Pseudocode Fuzzy Hash Match(AST)', 'Rare Pseudocode Fuzzy Hash Match(Normal)',
                 'Rare Pseudocode Fuzzy Hash Match(Reverse)']
        res = 0
        for rule in rules:
            sql = sql_dict[rule]
            res += self.insert_results(sql, 'results_fuzzy_code_hash')
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print('Code Hash Match:' + str(res))
        print("Code Hash Match {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))
        if res != 0:
            self.call_match()

    def do_perfect_match(self, module='match'):
        """
        do perfect match
        include Basic Features Match, Function Call Match, Constants Match, CFG Hash Match, Neighbor Match
        @param module : match module
        """
        if module.startswith('match'):
            self.af.save_functions(self.functions)
            self.af.save_callers(self.functions)
            self.bytes_hash_match()
            self.af.save_constants(self.functions)
            self.constants_match()
            self.af.update_cfg_hash(self.functions)
        elif module.startswith('init'):
            self.af.analyse_symbol()
            self.bytes_hash_match()
            self.constants_match()
        elif module.startswith('test'):
            self.bytes_hash_match()
            self.constants_match()
        self.cfg_hash_match()
        self.neighbor_match()

    def do_slow_match(self, module='match'):
        """
        do slow match
        @param module : match module
        """
        self.update_match_results()
        if module.startswith('match'):
            self.af.update_code(self.functions)
        self.code_match()
        self.code_hash_match()
        while True:
            s = self.neighbor_match()
            if s == 0:
                break


class MultipleMatch(Match):
    def __init__(self, bin_name, src_name):
        Match.__init__(self, bin_name, src_name)
        self.update_match_results()

    def do_swallow_match(self, row, sql_src):
        self.cur.execute(sql_src % row[0][2])
        src = self.cur.fetchone()
        if src is None:
            return 0
        if int(src[0]) in range(int(row[1]) - int(row[2]) - 1, int(row[1]) - int(row[2]) + 1):
            if int(src[2]) in self.src_matched:
                return 0
            l = (row[0][0], row[0][1], src[2], src[1], 'Swallow Match')
            return self.do_insert_results(l, 'results_multi')
        return 0

    def swallow_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results_multi()
        rows = sql_op.read_results_instr(self.src_name)
        self.conn, self.cur = sql_op.attach(self.src_name)
        sql_src_bck = """select instructions, name, address, numbers, numbers2 from diff.functions 
            where address > %s order by address
        """
        sql_src_fnt = """select instructions, name, address, numbers, numbers2 from diff.functions 
            where address < %s order by address desc
        """
        res = 0
        for row in rows:
            i = 0
            i += self.do_swallow_match(row, sql_src_fnt)
            i += self.do_swallow_match(row, sql_src_bck)
            res += i
            if i > 0:
                l = (str(row[0][0]), str(row[0][1]), str(row[0][2]), str(row[0][3]), str(row[0][4]))
                res += self.do_insert_results(l, 'results_multi')
        if self.cur is not None:
            self.cur.close()
            self.conn.close()
        time_elapsed = time.time() - t0
        print('Swallow Match:' + str(res))
        print('Swallow Match {:.0f}m {:.0f}s'.format(time_elapsed // 60, time_elapsed % 60))

    def linker_optimization_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules_name = ['Supplement Match', 'Linker Optimization Match',
                      'Same Bytes Hash Match']
        res = 0
        for rules in rules_name:
            sql = sql_dict[rules]
            res += self.insert_results(sql, 'results_multi')
        self.cur.close()
        self.conn.close()
        time_elapsed = time.time() - t0
        print('Linker Optimization Match:' + str(res))
        print("Linker Optimization Match {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def do_multiple_match(self):
        """
        do multiple match
        include Swallow Match and Bytes Hash Match
        """
        self.swallow_match()
        self.linker_optimization_match()


class FuzzyMatch(Match):
    def __init__(self, bin_name, src_name):
        Match.__init__(self, bin_name, src_name)
        self.af = AnalyseFunction(self.bin_name)
        print self.update_match_results()

    def delete_results(self, sql_op):
        sql = """delete from results_fuzzy where id not in (
                    select id from results_fuzzy group by bin_address order by ratio desc)
                    and ratio < 1.0
            """
        self.cur.execute(sql)
        self.conn.commit()
        rows = sql_op.read_results_fuzzy()
        res = 0
        for row in rows:
            if int(str(row[0])) in self.functions:
                self.functions.remove(int(str(row[0])))
                res += 1
        return res

    def score_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results_fuzzy()
        self.conn, self.cur = sql_op.attach(self.src_name)
        res = 0
        rules = ['Mnemonics Score Match', 'Constants Score Match', 'MD Index Score Match', 'KOKA Hash Score Match',
                 'Mnemonics Spp Match', 'Pseudocode Fuzzy Hash Match(Mixed)',
                 'Pseudocode Fuzzy Hash Match(AST)', 'Pseudocode Fuzzy Hash Match(Normal)',
                 'Pseudocode Fuzzy Hash Match(Reverse)']
        for rule in rules:
            sql = sql_dict[rule]
            self.insert_results(sql, 'results_fuzzy')
            res += self.delete_results(sql_op)
        self.cur.close()
        self.conn.close()

        time_elapsed = time.time() - t0
        print('Score Match:' + str(res))
        print("Score Match {:.0f}m {:.0f}s".format(time_elapsed // 60, time_elapsed % 60))

    def do_fuzzy_match(self):
        """
        do score match
        """
        self.score_match()
