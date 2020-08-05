# from idc import *
from perfect_match import PerfectMatch
from sql_opt import *
import time
t0 = time.time()
# sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
sqlite_db = "libcpp_tests_noSymbol.sqlite"
sym_db = "diff_symbol.sqlite"
pm = PerfectMatch(sqlite_db, sym_db)

pm.neighbor_match()
time_elapsed = time.time() - t0
print('Total time in {:.0f}m {:.0f}s'.format(
    time_elapsed // 60, time_elapsed % 60))