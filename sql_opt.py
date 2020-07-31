#!/usr/bin/python
import sqlite3


sql_dict = {}
sql_dict['strings_match'] = """select * from diff.constants where func_id in (
                select func_id from (
                    select * from diff.constants where LENGTH(constant) > %s group by constant having count(*) == 1
                ) 
                group by func_id having count(*) == %s
            )
            and constant in (
                select constant from diff.constants where LENGTH(constant) > %s group by constant having count(*) == 1
            )
                    """
sql_dict['Same Name Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                df.address src_address, 'Same Name Match' description
        from (select * from functions where name not like 'sub_%' and name not like 'nullsub_%' and name not like 'j_%')  f,
             diff.functions df
        where (df.mangled_function = f.mangled_function
            or df.name = f.name)
        """
sql_dict['Bytes Hash Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Bytes Hash Match' description
                    from functions f,
                        diff.functions df,
                        (select function_hash from functions group by function_hash having count(function_hash) == 1) rare_hash
                    where f.function_hash = df.function_hash
                    and f.function_hash = rare_hash.function_hash
                    and f.address not in (select bin_address from results)
            """
sql_dict['Rare Mnemonics Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Rare Mnemonics Match' description
                    from (select * from functions group by mnemonics having count(mnemonics) = 1) f,
                    (select * from diff.functions group by mnemonics having count(mnemonics) = 1) df
                    where f.mnemonics = df.mnemonics
                    and f.instructions = df.instructions
                    and f.instructions > 5 
                    and f.address not in (select bin_address from results)       
            """
sql_dict['Rare Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Rare Constants Match' description
                    from (select * from functions group by constants having count(constants) = 1) f,
                    (select * from diff.functions group by constants having count(constants) = 1) df
                    where f.constants = df.constants
                    and f.instructions = df.instructions
                    and f.address not in (select bin_address from results)       
            """
sql_dict['Mnemonics Constants match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Mnemonics and Constants Match' description
                    from functions f,
                        diff.functions df
                    where f.mnemonics = df.mnemonics
                    and f.constants = df.constants
                    and f.instructions = df.instructions
                    and f.instructions > 5
                    and f.constants_count = df.constants_count
                    and f.constants_count > 0    
                    and f.address not in (select bin_address from results)  
            """
sql_dict['Rare Md_Index Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'Rare MD Index Match' description
                from (select * from main.functions where md_index != 0 group by md_index having count(*) == 1) f,
                     (select * from diff.functions where md_index != 0 group by md_index having count(*) == 1) df
                where f.md_index = df.md_index
                and f.nodes > 5
                and f.address not in (select bin_address from results)
        """
sql_dict['Rare KOKA Hash Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'Rare KOKA Hash Match' description
           from (select * from main.functions where kgh_hash != 0 group by kgh_hash having count(*) == 1) f,
                (select * from diff.functions where kgh_hash != 0 group by kgh_hash having count(*) == 1) df
                where f.kgh_hash = df.kgh_hash
                and f.nodes > 5
                and f.address not in (select bin_address from results) 
"""
sql_dict['Md_Index Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'MD_Index and Constants Match' description
                from functions f,
                     diff.functions df
                where f.md_index = df.md_index
                and f.nodes > 5
                and f.constants = df.constants
                and f.constants_count > 0
                and f.address not in (select bin_address from results)
        """
sql_dict['KOKA Hash Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'KOKA Hash and Constants Match' description
                from functions f,
                     diff.functions df
                where f.kgh_hash = df.kgh_hash
                and f.nodes > 5
                and f.constants = df.constants
                and f.constants_count > 0
                and f.address not in (select bin_address from results)
        """
sql_dict['neighbor_match'] = """select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Bytes Hash Match' description
                    from functions f,
                        diff.functions df
                    where f.function_hash = df.function_hash
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Mnemonics Match' description
                    from functions f,
                        diff.functions df
                    where f.mnemonics = df.mnemonics
                    and f.instructions = df.instructions
                    and f.instructions > 5 and df.instructions > 5
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'md_index Match' description
                    from functions f,
                        diff.functions df
                    where f.md_index = df.md_index
                    and f.nodes > 5
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'kgh_hash Match' description
                    from functions f,
                        diff.functions df
                    where f.kgh_hash = df.kgh_hash
                    and f.nodes > 5
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Constants Match' description
                    from functions f,
                        diff.functions df
                    where f.constants = df.constants
                    and f.constants_count > 0
                    and f.address not in (select bin_address from results)
                    union
                    select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'MD_Index and Constants Match' description
                    from functions f,
                        diff.functions df
                    where f.md_index = df.md_index
                    and f.nodes > 5
                    and f.constants = df.constants
                    and f.constants_count > 1
                    and f.address not in (select bin_address from results)
        """

sql_dict['Test Bytes Hash Match'] = """select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Bytes Hash Match' description
                    from functions f,
                        diff.functions df
                    where f.function_hash = df.function_hash
                    and f.instructions > 5
                    and f.address not in (select bin_address from results)
                    group by f.function_hash
"""

class SqlOperate:
    def __init__(self, name):
        self.db_name = name
        self.conn = None
        self.cur = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()
        self.conn.text_factory = str
        self.conn.row_factory = sqlite3.Row
        return self.conn, self.cur

    def attach(self, name):
        self.connect()
        try:
            self.cur.execute('attach "%s" as diff' % name)
            self.conn.commit()
        except:
            print "sqlite attach error"
        return self.conn, self.cur

    def create_results(self):
        self.connect()
        sql = """create table if not exists results (
            bin_address text,
            bin_name varchar(255), 
            src_address text unique,
            src_name varchar(255), 
            description varchar(255),
            primary key(src_name))"""
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create results error")
        finally:
            self.cur.close()

    def create_functions(self):
        self.connect()
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
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create functions error!")
        finally:
            self.cur.close()

    def create_constants(self):
        self.connect()
        sql = """create table if not exists constants (
                func_id integer not null references functions(id) on delete cascade,
                constant text not null,
                primary key(func_id, constant))
        """
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create constants error!")
        finally:
            self.cur.close()

    def create_callers(self):
        self.connect()
        sql = """create table if not exists callers(
                caller_id integer not null references functions(id) on delete cascade,
                caller_address text not null,
                callee_address text not null,
                primary key(caller_address, callee_address)
        """
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create callers error!")
        finally:
            self.cur.close()

    def read_results(self):
        self.connect()
        sql = """select src_address, bin_address from results where 
            description = 'Rare MD Index Match'
            and bin_address in (select address from functions where instructions > 5)
        """
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        sum = 0
        for row in rows:
            print row[0] + '->' + row[1]
            sum += 1
        print sum

    def test_sql(self, name, s):
        self.attach(name)
        self.cur.execute(sql_dict[s])
        rows = self.cur.fetchall()
        for row in rows:
            print str(row[4]) + '->' + str(row[0])
        print len(rows)


"""
name = "C:\\Users\\Admin\\Desktop\\data6\\libcpp_tests_noSymbol.sqlite"
src_name = "C:\\Users\\Admin\\Desktop\\data6\\diff.sqlite"
sql_opt = SqlOperate(name)
sql_opt.test_sql(src_name, 'Test Bytes Hash Match')

conn, cur = sql_opt.attach(src_name)
cur.execute(sql_dict['cfg_hash_match'])
rows = cur.fetchall()
for row in rows:
    print str(row[4]) + '->' + str(row[0])
print len(rows)
"""