from test.sql_opt import SqlOperate
import time


class NeighborMatch:
    def __init__(self, bin_name, src_name):
        """self.bin_name = sr.bin_name
        self.src_name = sr.src_name
        self.src_matched = sr.src_matched
        self.bin_matched = sr.bin_matched
        self.functions = sr.functions
        self.has_results = sr.has_results
        self.has_functions = sr.has_functions"""
        self.bin_name = bin_name
        self.src_name = src_name
        self.has_results = True
        self.has_functions = True
        self.conn = None
        self.cur = None
        self.get_sql_db()
        self.neighbor_match()

    def get_sql_db(self):
        sql_op = SqlOperate(self.bin_name)
        if self.has_results is False:
            sql_op.create_results()
        self.has_results = True
        if self.has_functions is False:
            sql_op.create_functions()
        self.has_functions = True
        self.conn, self.cur = sql_op.connect()

    def neighbor_match(self):
        t0 = time.time()

        self.cur.execute('attach "%s" as diff' % self.src_name)
        self.conn.commit()

        sql = """select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Bytes Hash Match' description
                    from functions f,
                        diff.functions df,
                        (select function_hash from functions group by function_hash having count(bytes_hash) != 1) rare_hash
                    where f.function_hash = df.function_hash
                    and f.function_hash = rare_hash.function_hash
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Mnemonics Match' description
                    from functions f,
                        diff.functions df,                        
                        (select mnemonics from functions group by mnemonics having count(mnemonics) != 1) rare_mnems
                    where f.mnemonics = df.mnemonics
                    and f.mnemonics = rare_mnems.mnemonics
                    and f.instructions = df.instructions
                    and f.instructions > 5 and df.instructions > 5
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'md_index Match' description
                    from functions f,
                        diff.functions df
                    where f.md_index = df.md_index
                    and f.nodes > 10
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'kgh_hash Match' description
                    from functions f,
                        diff.functions df
                    where f.kgh_hash = df.kgh_hash
                    and f.nodes > 10
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Constants Match' description
                    from functions f,
                        diff.functions df
                    where f.constants = df.constants
                    and f.constants_count > 0
                    and f.address not in (select bin_address from results)
        """
        sql_results = """select * from results where bin_address = %s
        """
        sql_pre = """select address from functions where address < %s
                    order by address desc    
        """
        sql_bck = """select address from functions where address > %s
                    order by address
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
            # print str(row[0]) + "has pre matched neighbor"
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
                print str(src[0][2]) + "->" + bin_func
                sum += 1
        print sum

        self.cur.close()
        time_elapsed = time.time() - t0
        print('Training complete in {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))


bin_name = "C:\\Users\\Admin\\Desktop\\data5\\libcpp_tests_noSymbol.sqlite"
src_name = "C:\\Users\\Admin\\Desktop\\data5\\libcpp_empty_test.sqlite"
n = NeighborMatch(bin_name, src_name)
