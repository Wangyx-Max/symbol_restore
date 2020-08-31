from score import *
from sql_opt import *




sqlite_db = "C:\\Users\\Admin\\Desktop\\data8\\libcpp_tests_noSymbol.sqlite"
sym_db = "C:\\Users\\Admin\\Desktop\\data8\\diff.sqlite"
rules = ['Same Mnemonics Match']
for rule in rules:
    sql = sql_dict[rule]
    sql_op = SqlOperate(sqlite_db)
    sql_op.attach(sym_db)
    sql_op.cur.execute(sql)
    rows = sql_op.cur.fetchall()
    print rule + ' ' + str(len(rows))
    for row in rows:
        print str(row[0]) + '->' + str(row[4])
        print make_score(row, sql_op.cur)
        print '----------------------------'








"""
class AnalyseCodeHash(AnalyseFunction):
    def __init__(self, name):
        AnalyseFunction.__init__(self, name)

    def read_code_hash(self, f):
        if func_check(f) is False:
            return False
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
        ch = CodeHash()
        return ch.get_code_hash(f, pseudo)


name = "C:\\sym_restore\\Sample2\\diff.sqlite"
ach = AnalyseCodeHash(name)
ach.update_code_hash(ach.functions)
"""



"""
def quick_ratio(buf1, buf2):
    try:
        if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
            return 0
        s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
        return s.quick_ratio()
    except:
        print("quick_ratio:", str(sys.exc_info()[1]))
        return 0


def check_ratio(pseudo1, pseudo2, asm1, asm2, md1, md2):
    fratio = quick_ratio
    decimal_values = "{0:.2f}"
    md1 = float(md1)
    md2 = float(md2)
    v1 = 0
    if pseudo1 is not None and pseudo2 is not None and pseudo1 != "" and pseudo2 != "":
        if pseudo1 != "" or pseudo2 != "":
            v1 = fratio(pseudo1, pseudo2)
            v1 = float(decimal_values.format(v1))

    v2 = fratio(asm1, asm2)
    v2 = float(decimal_values.format(v2))

    v4 = 0.0
    if md1 == md2 and md1 > 0.0:
        # A MD-Index >= 10.0 is somehow rare
        if md1 > 10.0:
            return 1.0
        v4 = min((v1 + v2 + 3.0) / 4, 1.0)

    r = max(v1, v2, v4)
    return r
t0 = time.time()
sqlite_db = "C:\\sym_restore\\Sample\\noSymbol_tests.sqlite"
sym_db = "C:\\sym_restore\\Sample\\diff.sqlite"
sql_op = SqlOperate(sqlite_db)
sql_op.attach(sym_db)
sql = "select f.clean_pseudo, df.clean_pseudo, f.clean_assembly, df.clean_assembly, f.md_index, df.md_index 
        from functions f, diff.functions df
        where f.address = 218312 and df.address = 2835574
"
sql = sql_dict['Mnemonics Score Match']
sql_op.cur.execute(sql)
rows = sql_op.cur.fetchall()

res = 0
for row in rows:
    r = check_ratio(str(row[8]), str(row[9]), str(row[6]), str(row[7]), str(row[10]), str(row[11]))
    if r == 1.0:
        print str(row[0]) + '->' + str(row[4])
        res += 1
print len(rows)
print res"""
"""

    def get_functions(self):
        sql_op = SqlOperate(self.bin_name)
        rows = sql_op.read_results()
        for row in rows:
            self.functions.append(row[0])

    def do_caller_match(self):
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        rows = sql_op.read_results()
        if len(rows) == 0:
            return
        # print len(rows)
        self.conn, self.cur = sql_op.attach(self.src_name)
        sql_bin = "select callers, callers_count, name, numbers, numbers_count, numbers2, numbers2_count, instructions from functions where address = %s
                "
        sql_src = "select callers, callers_count, name, numbers, numbers_count, numbers2, numbers2_count, instructions from diff.functions where address = %s
                "
        res = set()
        sum = 0
        for row in rows:
            # print row
            self.cur.execute(sql_bin % row[0])
            bin = self.cur.fetchone()
            self.cur.execute(sql_src % row[2])
            src = self.cur.fetchone()
            if bin and src and int(bin[1]) == int(src[1]) and int(src[1]) > 0:
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
                        if bin_c and src_c:
                            l = (bin_addr, str(bin_c[2]), src_addr, str(src_c[2]), 'Caller Match')
                            res.add(l)
                            print str(bin_addr) + '->' + str(src_addr)
                            if int(bin_addr) in self.functions:
                                self.functions.remove(int(bin_addr))
                            sum += 1
        return sum


name = "C:\\Users\\Admin\\Desktop\\data7\\libcpp_tests_noSymbol.sqlite"
diff_name = "C:\\Users\\Admin\\Desktop\\data7\\diff.sqlite"
pm = PerfectMatch(name, diff_name)
pm.get_functions()
pm.do_caller_match()
"""
"""
name = "C:\\Users\\Admin\\Desktop\\sym_restore\\Sample2\\libMyGame.sqlite"
sql = "update or ignore functions set name_hash = ?, mangled_hash = ? where address = ?"
sql_op = SqlOperate(name)
conn, cur = sql_op.connect()
af = AnalyseFunction(name)
for f in list(Functions(MinEA(), MaxEA())):
    if af.func_check(f) is False:
        continue
    func = get_func(f)
    name = GetFunctionName(int(f))
    true_name = name
    demangle_name = Demangle(name, INF_SHORT_DN)
    if demangle_name is None or demangle_name == "":
        demangle_name = None

    if demangle_name is not None:
        name = demangle_name

    name_hash = md5(name).hexdigest()
    true_name_hash = None
    if demangle_name is not None:
        true_name_hash = md5(demangle_name).hexdigest()
    props = af.create_sql_props((name_hash, true_name_hash, f))
    cur.execute(sql, props)
    conn.commit()
cur.close()
"""
"""
name = "C:\\Users\\Admin\\Desktop\\data7\\diff.sqlite"
af = AnalyseFunction(name)
af.save_constants(list(Functions(MinEA(), MaxEA())))
"""

"""
class PerfectMatch:
    def __init__(self, bin_name, src_name):
        self.bin_name = bin_name
        self.src_name = src_name
        self.src_matched = set()  # func_id
        self.bin_matched = set()  # startEA of a function
        # self.analyse_func = AnalyseFunction(self.bin_name)
        self.conn = False
        self.cur = False
        self.functions = []

    def do_match_string(self, length, strings):
        sql = sql_dict['strings_match']

        self.cur.execute(sql % (str(length), str(length)))

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
                        result_tmp[str(string)].append(str(func.startEA))
                    except:
                        result_tmp[str(string)] = [str(func.startEA)]

        funcs_id = {}
        for key, value in result_tmp.items():
            value = list(value)
            if len(value) == 1:
                funcs_id[str(sql_result[str(value[0])])] = key
        res = set()
        sql = "select name, address from diff.functions where id = %s"

        for func_id in set(funcs_id.keys()):
            self.cur.execute(sql % str(func_id))
            row = self.cur.fetchone()
            address = int(funcs_id[func_id])
            self.bin_matched.add(str(funcs_id[func_id]))
            self.src_matched.add(str(func_id))
            if address in self.functions:
                self.functions.remove(address)
            l = (str(address), str(GetFunctionName(address)), str(row[1]), str(row[0]), 'String Match')
            res.add(l)

        return len(res)


    def strings_match(self):
        strings = []
        for string in Strings():
            if len(str(string)) > 5:
                strings.append(string)
        # print len(strings)

        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)

        sum = 0
        sum = self.do_match_string(25, strings)
        if self.cur is not None:
            self.cur.close()
        print sum


sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
sym_db = "diff.sqlite"
pm = PerfectMatch(sqlite_db, sym_db)
pm.strings_match()
"""


import time
from sql_opt import *


class PerfectMatch:
    def __init__(self, bin_name, src_name):
        self.bin_name = bin_name
        self.src_name = src_name
        self.src_matched = set()  # func_id
        self.bin_matched = set()  # startEA of a function
        # self.analyse_func = AnalyseFunction(self.bin_name)
        self.conn = False
        self.cur = False
        self.functions = []

    def do_neighbor_match(self):
        t0 = time.time()
        sql_op = SqlOperate(self.bin_name)
        sql_op.create_results()
        self.conn, self.cur = sql_op.attach(self.src_name)
        rules = ['Mnemonics Neighbor Match']
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

            sum += self.do_neighbor_match_unilateral(pairs, rule)
        if self.cur is not None:
            self.cur.close()

        time_elapsed = time.time() - t0
        print('Neighbor Match:' + str(sum))
        print('Neighbor Match {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))
        return sum

    def do_neighbor_match_unilateral(self, pairs, rule):
        sql_results = """select * from results where bin_address = %s
                                    """
        sql_pre = """select address from functions where address < %d
                                                order by address desc    
                                    """
        sql_bck = """select address from functions where address > %d
                                                order by address
                                    """
        sql_bin = """select name, address from functions where address = %s
                                    """
        sql_src_pre = """select id, name, address from diff.functions where address > %d order by address
                                    """
        sql_src_bck = """select id, name, address from diff.functions where address < %d order by address desc
                                    """
        sum = 0
        for bin_func in pairs.keys():
            if int(bin_func) != 218076:
                continue
            print pairs[bin_func]
            self.cur.execute(sql_pre % int(bin_func))
            one_p = self.cur.fetchone()
            self.cur.execute(sql_bck % int(bin_func))
            one_b = self.cur.fetchone()
            print one_p, one_b
            if one_p is not None:
                self.cur.execute(sql_results % str(one_p[0]))
                pre = self.cur.fetchall()
                if len(pre) != 1:
                    continue
                self.cur.execute(sql_src_pre % int(pre[0][2]))
                src = self.cur.fetchone()
                if src and str(src[2]) in pairs[bin_func]:
                    self.cur.execute(sql_bin % bin_func)
                    bin = self.cur.fetchone()
                    print str(bin[1]) + '->' + str(src[2])
            if one_b is not None:
                print 'here'
                self.cur.execute(sql_results % str(one_b[0]))
                bck = self.cur.fetchall()
                print bck
                if len(bck) != 1:
                    continue
                self.cur.execute(sql_src_bck % int(bck[0][2]))
                src = self.cur.fetchone()
                print src
                if src and str(src[2]) in pairs[bin_func]:
                    self.cur.execute(sql_bin % bin_func)
                    bin = self.cur.fetchone()
                    print str(bin[1]) + '->' + str(src[2])
        return sum


sqlite_db = "C:\\Users\\Admin\\Desktop\\sym_restore\\Sample\\noSymbol_tests.sqlite"
sym_db = "C:\\Users\\Admin\\Desktop\\sym_restore\\Sample\\diff.sqlite"
pm = PerfectMatch(sqlite_db, sym_db)
pm.do_neighbor_match()