from sql_opt import SqlOperate

bin_name = "C:\\Users\\Admin\\Desktop\\data4\\string_match.sqlite"
src_name = "C:\\Users\\Admin\\Desktop\\data4\\symbol_string_match.sqlite"
sql_op = SqlOperate(bin_name)
conn, cur = sql_op.attach(src_name)

sql = """select distinct func_id from constants 
        group by func_id having count(func_id) > 1
"""
cur.execute(sql)
bin_rows = cur.fetchall()
bin_dict = {}
sql = """select constant from constants where func_id = %s"""
for bin_row in bin_rows:
    cur.execute(sql % str(bin_row[0]))
    constants = cur.fetchall()
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
cur.execute(sql)
src_rows = cur.fetchall()
src_dict = {}
sql = """select constant from diff.constants where func_id = %s"""
for src_row in src_rows:
    cur.execute(sql % str(src_row[0]))
    constants = cur.fetchall()
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
        sql = "select address from functions where id = %d"
        cur.execute(sql % int(func_id))
        bin_addr = cur.fetchone()
        sql = "select address from diff.functions where id = %d"
        cur.execute(sql % int(src_func_id))
        src_name = cur.fetchone()
        print hex(int(src_name[0])) + "->" + hex(int(bin_addr[0]))
        sum += 1
print sum

