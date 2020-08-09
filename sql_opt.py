#!/usr/bin/python
import sqlite3
import json


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
sql_dict['Rare Bytes Hash Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Bytes Hash Match' description
                    from (select * from functions group by function_hash having count(function_hash) = 1) f,
                    diff.functions df
                    where f.function_hash = df.function_hash
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
            """
sql_dict['Rare Mnemonics Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Rare Mnemonics Match' description
                    from (select * from functions group by mnemonics, numbers, numbers2 having count(*) = 1) f,
                    diff.functions df
                    where f.mnemonics = df.mnemonics
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
                    and f.instructions > 2
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
            """
sql_dict['Rare Numbers Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Rare Numbers Match' description
                    from (select * from functions where numbers_count > 5 or numbers2_count > 3 group by numbers, numbers2 having count(*) = 1) f,
                    diff.functions df
                    where f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""
sql_dict['Rare Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Rare Constants Match' description
                    from functions f,
                    (select * from diff.functions where constants_count > 0 group by constants, numbers, numbers2 having count(*) = 1) df
                    where f.constants = df.constants
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
                    and f.address not in (select bin_address from results) 
                    group by src_func_id having count(src_func_id) = 1
            """
sql_dict['Mnemonics Constants match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Mnemonics and Constants Match' description
                    from functions f,
                        (select * from diff.functions group by mnemonics, constants having count(*) = 1) df
                    where f.mnemonics = df.mnemonics
                    and f.constants = df.constants
                    and f.constants_count > 1
                    and f.address not in (select bin_address from results)
                    group by src_func_id having count(src_func_id) = 1  
            """
sql_dict['Rare Md_Index Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'Rare MD Index Match' description
                from functions f,
                     (select * from diff.functions where md_index != 0 group by md_index having count(*) == 1) df
                where f.md_index = df.md_index
                and (f.size = df.size or f.instructions = df.instructions or 
                        (f.numbers = df.numbers and f.numbers_count > 0))
                and f.address not in (select bin_address from results)
                group by src_func_id having count(src_func_id) = 1 
        """
sql_dict['Rare KOKA Hash Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'Rare KOKA Hash Match' description
           from functions f,
                (select * from diff.functions where kgh_hash != 0 group by kgh_hash having count(*) == 1) df
                where f.kgh_hash = df.kgh_hash
                and (f.size = df.size or f.instructions = df.instructions or 
                        (f.numbers = df.numbers and f.numbers_count > 0) )
                and f.address not in (select bin_address from results)
                group by src_func_id having count(src_func_id) = 1 
"""
sql_dict['Md_Index Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'MD_Index and Constants Match' description
                from functions f,
                     (select * from diff.functions where md_index != 0 group by md_index, constants, numbers having count(*) == 1) df
                where f.md_index = df.md_index
                and f.nodes > 5
                and ((f.constants = df.constants and f.constants_count > 0)
                or (f.numbers = df.numbers and f.numbers_count > 0))
                and (f.size = df.size or f.instructions = df.instructions 
                        or (f.numbers = df.numbers and f.numbers_count > 0) )
                and f.address not in (select bin_address from results)
                group by src_func_id having count(src_func_id) = 1 
        """
sql_dict['KOKA Hash Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'MD_Index and Constants Match' description
                from functions f,
                     (select * from diff.functions where md_index != 0 group by kgh_hash, constants, numbers having count(*) == 1) df
                where f.kgh_hash = df.kgh_hash
                and f.nodes > 5
                and ((f.constants = df.constants and f.constants_count > 0)
                or (f.numbers = df.numbers and f.numbers_count > 0))
                and (f.size = df.size or f.instructions = df.instructions 
                        or (f.numbers = df.numbers and f.numbers_count > 0) )
                and f.address not in (select bin_address from results)
                group by f.address having count(f.address) = 1 
        """
sql_dict['Bytes Hash Neighbor Match'] = """select distinct f.address bin_addr, f.name bin_name, df.id src_id, df.name src_name, df.address src_addr,
                    'Bytes Hash Neighbor Match' description, f.id bin_id
                    from functions f,
                        diff.functions df
                    where f.function_hash = df.function_hash
                    and f.address not in (select bin_address from results)
        """
sql_dict['Mnemonics Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Mnemonics Neighbor Match' description, f.id bin_id
                    from functions f,
                        diff.functions df
                    where f.mnemonics = df.mnemonics
                    and f.instructions = df.instructions
                    and f.instructions > 5
                    and f.address not in (select bin_address from results)
        """
sql_dict['Constants Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Constants Neighbor Match' description, f.id bin_id
                    from functions f,
                        diff.functions df
                    where f.constants = df.constants
                    and f.constants_count > 0
                    and f.address not in (select bin_address from results)
        """
sql_dict['MD Index Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'MD Index Neighbor Match' description, f.id bin_id
                    from (select * from functions where md_index != 0) f,
                        (select * from diff.functions where md_index != 0) df
                    where f.md_index = df.md_index
                    and f.size = df.size
                    and f.instructions = df.instructions
                    and f.address not in (select bin_address from results)
        """
sql_dict['KOKA Hash Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'KOKA Hash Neighbor Match' description, f.id bin_id
                    from (select * from functions where kgh_hash != 0) f,
                        (select * from diff.functions where kgh_hash != 0) df
                    where f.kgh_hash = df.kgh_hash
                    and f.size = df.size
                    and f.instructions = df.instructions
                    and f.address not in (select bin_address from results)
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
            numbers text,
            numbers_count integer,
            numbers2 text,
            numbers2_count integer,
            assembly_addrs text,
            kgh_hash text,
            callers text,
            callers_count integer) """
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
                call_address text not null,
                callee_address text not null,
                primary key(caller_address, callee_address))
        """
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create callers error!")
        finally:
            self.cur.close()

    def read_functions(self, bin_address, src_address=0, src_name=None):
        self.connect()
        sql = """select * from functions where address = %s
        """
        self.cur.execute(sql % bin_address)
        bin = self.cur.fetchone()
        src = None
        if src_name is not None:
            self.attach(src_name)
            sql = """select * from diff.functions where address = %s
            """
            self.cur.execute(sql % src_address)
            src = self.cur.fetchone()
            self.cur.close()
        if self.cur is not None:
            self.cur.close()
        return bin, src

    def read_results(self):
        self.connect()
        sql = """select * from results"""
        self.cur.execute(sql)
        res = self.cur.fetchall()
        self.cur.close()
        return res

    def read_constants(self, name=None):
        if name is None:
            self.connect()
            sql_func_id = """select distinct func_id from constants 
                        group by func_id having count(func_id) > 1
                """
            sql_cons = """select constant from constants where func_id = %s"""
        else:
            self.attach(name)
            sql_func_id = """select distinct func_id from diff.constants 
                        group by func_id having count(func_id) > 1
                """
            sql_cons = """select constant from diff.constants where func_id = %s"""
        self.cur.execute(sql_func_id)
        rows = self.cur.fetchall()
        dict = {}
        for row in rows:
            self.cur.execute(sql_cons % str(row[0]))
            constants = self.cur.fetchall()
            new_constants = []
            for constant in constants:
                new_constants.append(str(constant))
            new_constants = json.dumps(new_constants)
            try:
                dict[new_constants].append(str(row[0]))
            except:
                dict[new_constants] = [str(row[0])]
        if self.cur is not None:
            self.cur.close()
        return dict

    def read_results_des(self, des, output=False):
        self.connect()
        sql = """select * from results where description == %s
        """
        self.cur.execute(sql % des)
        rows = self.cur.fetchall()
        if output is True:
            sum = 0
            for row in rows:
                print row[0] + '->' + row[2]
                sum += 1
            print sum
        self.cur.close()
        return rows

    def read_results_test(self, src_name, attr, des=None):
        self.attach(src_name)
        if des is None:
            sql = """select src_address, bin_address, description from results
            """
            self.cur.execute(sql)
        else:
            sql = """select src_address, bin_address, description from results where description == %s
            """
            self.cur.execute(sql % des)
        sql_bin = """select %s from functions where address = %s 
        """
        sql_src = """select %s from diff.functions where address = %s 
        """

        rows = self.cur.fetchall()
        sum = 0
        s = 0
        for row in rows:
            sum += 1
            self.cur.execute(sql_bin % (attr, row[1]))
            bin = self.cur.fetchone()
            self.cur.execute(sql_src % (attr, row[0]))
            src = self.cur.fetchone()
            if bin and src and int(bin[0]) != int(src[0]):
                if des is None:
                    if row[2] == 'Caller Match' or row[2] == 'Rare Mnemonics' or row[2] == 'Callee Match' or str(row[2]).endswith('Neighbor Match'):
                        continue
                    print row[2]
                print bin[0]
                print src[0]
                print row[1] + '->' + row[0]
                s += 1
        print sum, s

    def test_sql_dict(self, name, key, output=False):
        self.attach(name)
        sql = sql_dict[key]
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        if output is True:
            for row in rows:
                print hex(int(row[0])) + '->' + hex(int(row[4]))
            print len(rows)
        return rows
