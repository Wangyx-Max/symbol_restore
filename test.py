from sql_opt import SqlOperate

bin_name = "C:\\Users\\Admin\\Desktop\\data_clean_code\\libcpp_tests_noSymbol.sqlite"
sql_opt = SqlOperate(bin_name)
src_name = "C:\\Users\\Admin\\Desktop\\data_clean_code\\diff.sqlite"
conn, cur = sql_opt.attach(src_name)
sql = "select bin_address, src_address, description from results"
sql_bin = "select clean_assembly from functions where address = %s"
sql_src = "select clean_assembly from diff.functions where address = %s"
cur.execute(sql)
rows = cur.fetchall()
sql = """
create table if not exists tmp (
            bin_address text, 
            bin_clean_assembly text,
            src_address text unique,
            src_clean_assembly text,
            description varchar(255))
"""
cur.execute(sql)
sql_insert = """
insert or ignore into tmp (bin_address, bin_clean_assembly, src_address, src_clean_assembly, description)
values(?, ?, ?, ?, ?)
"""
for row in rows:
    cur.execute(sql_bin % str(row[0]))
    bin = cur.fetchone()
    cur.execute(sql_src % str(row[1]))
    src = cur.fetchone()
    l = [str(row[0]), str(bin[0]), str(row[1]), str(src[0]), str(row[2])]
    cur.execute(sql_insert, l)
    conn.commit()
