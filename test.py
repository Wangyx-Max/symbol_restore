# from idc import *
from perfect_match import PerfectMatch
from sql_opt import *
import time
t0 = time.time()
# sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
sqlite_db = "libcpp_tests_noSymbol.sqlite"
sym_db = "diff.sqlite"
sql_op = SqlOperate(sqlite_db)
rows = sql_op.read_results()
pm = PerfectMatch(sqlite_db, sym_db)
for row in rows:
    if int(row[0]) in pm.functions:
        pm.functions.remove(int(row[0]))

pm.caller_match_3()
time_elapsed = time.time() - t0
print('Total time in {:.0f}m {:.0f}s'.format(
    time_elapsed // 60, time_elapsed % 60))