from adap_show import *
from adap_match import *
import time


t0 = time.time()
sqlite_db = "C:\\Users\\Admin\\Desktop\\data9\\libcpp_tests_noSymbol.sqlite"
sym_db = "C:\\Users\\Admin\\Desktop\\data9\\diff.sqlite"
"""
mm = MultipleMatch(sqlite_db, sym_db)
mm.do_multiple_match()
show_all_results(sqlite_db, sym_db, 'Multiple Match')
"""
hide_wait_box()
fm = FuzzyMatch(sqlite_db, sym_db)
fm.do_fuzzy_match()
show_all_results(sqlite_db, sym_db, 'Fuzzy Match')


"""
t0 = time.time()
sqlite_db = "C:\\sym_restore\\Sample\\noSymbol_tests.sqlite"
sym_db = "C:\\sym_restore\\Sample\\diff.sqlite"
mm = MultipleMatch(sqlite_db, sym_db)
mm.do_multiple_match()
"""
"""
t0 = time.time()
sqlite_db = "C:\\sym_restore\\Sample\\noSymbol_tests.sqlite"
sym_db = "C:\\sym_restore\\Sample\\diff.sqlite"
fm = FuzzyMatch(sqlite_db, sym_db)
fm.do_fuzzy_match()
"""
"""
sql_op = SqlOperate(sqlite_db)
pm = PerfectMatch(sqlite_db, sym_db)
while True:
    if pm.neighbor_match() == 0:
        break
mm = MultipleMatch(sqlite_db, sym_db)
mm.do_multiple_match()"""

"""rows = sql_op.read_results_fuzzy(sym_db, 'md_index')
# rows = sql_op.read_results_multi()
c = PerfectChoose('test', sqlite_db, sym_db, rows)
c.show()"""

"""
t0 = time.time()
# sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
sqlite_db = "C:\\Users\\Admin\\Desktop\\sym_restore\\Sample\\noSymbol_tests.sqlite"
sym_db = "C:\\Users\\Admin\\Desktop\\sym_restore\\Sample\\diff.sqlite"
sql_op = SqlOperate(sqlite_db)
conn, cur = sql_op.attach(sym_db)
sql = "select * from(
select f.address ,r.src_address, '  matched' state, r.description, f.name from functions f, results r where f.address in (select bin_address from results) and f.address = r.bin_address
union
select address ,'0000000', 'unmatched','unmatched', name from functions where address not in (select bin_address from results)
)  order by address
"
cur.execute(sql)
rows = cur.fetchall()
for row in rows:
    print str(row[0]) + ' (' + str(row[4]) + ') ->' + str(row[1]) + ' ' + row[2] + ' ' + row[3]
# sql_op.read_results_test(sym_db, 'instructions', "\'Constants Neighbor Match Test\'")"""
"""
rows = sql_op.read_results()
s = 0
print len(rows)
for row in rows:
    if str(row[1]).startswith('sub_') or str(row[1]).startswith('nullsub_'):
        print row[0] + '->' + row[2] + ' ' + row[4]
        s += 1
print s
"""

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