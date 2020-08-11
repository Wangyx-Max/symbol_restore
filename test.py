# from idc import *
# from perfect_match import PerfectMatch
from sql_opt import *
import time

t0 = time.time()
# sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
sqlite_db = "C:\\Users\\Admin\\Desktop\\sym_restore\\Sample2\\results.sqlite"
sym_db = "C:\\Users\\Admin\\Desktop\\sym_restore\\Sample\\diff.sqlite"
sql_op = SqlOperate(sqlite_db)
rows = sql_op.read_results()
s = 0
print len(rows)
for row in rows:
    if str(row[1]).startswith('sub_') or str(row[1]).startswith('nullsub_'):
        print row[0] + '->' + row[2] + ' ' + row[4]
        s += 1
print s


"""
rows = sql_op.read_results_des("\'Mnemonics and Constants Match\'")
compere_db = "C:\\Users\\Admin\\Desktop\\data6\\results.db"
sql_op = SqlOperate(compere_db)
compere_rows = sql_op.read_results()
arr = {}
for row in compere_rows:
    arr[row[0]] = [row[2], row[4]]
for row in rows:
    if row[0] not in arr.keys():
        print row[0] + '->' + row[2]
    elif arr[row[0]][0] != row[2]:
        print row[0] + '->' + row[2] + '  might wrong  ' + arr[row[0]][0] + ' ' + arr[row[0]][1]
"""


"""
sql = "select * from diff.results
"

cur.execute(sql)
rows = cur.fetchall()
org = set()
for row in rows:
    org.add(str(row[0]))
sql = "select * from results where description = 'Mnemonics and Constants Match'"
sql_where = "select src_address, description from diff.results where bin_address = %s
"
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
"""


time_elapsed = time.time() - t0
print('Total time in {:.0f}m {:.0f}s'.format(
    time_elapsed // 60, time_elapsed % 60))