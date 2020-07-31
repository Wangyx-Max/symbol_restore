from idc import *
from perfect_match import PerfectMatch

t0 = time.time()
sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
sym_db = "diff.sqlite"
pm = PerfectMatch(sqlite_db, sym_db)
pm.do_perfect_match()
time_elapsed = time.time() - t0
print('Total time in {:.0f}m {:.0f}s'.format(
    time_elapsed // 60, time_elapsed % 60))