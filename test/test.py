# from idc import *
# from perfect_match import PerfectMatch
from sql_opt import *
import time

t0 = time.time()
# sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
sqlite_db = "C:\\Users\\Admin\\Desktop\\data7\\libcpp_tests_noSymbol.sqlite"
sym_db = "C:\\Users\\Admin\\Desktop\\data6\\results.db"
sql_op = SqlOperate(sqlite_db)
conn, cur = sql_op.attach(sym_db)
sql = """select * from diff.results
"""
cur.execute(sql)
rows = cur.fetchall()
org = set()
for row in rows:
    org.add(str(row[0]))
sql = """select * from results where description = 'Rare Numbers Match'"""
sql_where = """select src_address, description from diff.results where bin_address = %s
"""
cur.execute(sql)
rows = cur.fetchall()
sum = 0
for row in rows:
    if str(row[0]) not in org:
        print row[0] + '->' + row[2]
        sum += 1
    else:
        cur.execute(sql_where % str(row[0]))
        src = cur.fetchone()
        if src is not None and src[0] != row[2]:
            print row[0] + '->' + row[2] + '  -Wrong??' + src[1] + src[0]
print sum

time_elapsed = time.time() - t0
print('Total time in {:.0f}m {:.0f}s'.format(
    time_elapsed // 60, time_elapsed % 60))