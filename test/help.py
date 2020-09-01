from perfect_match import *

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
