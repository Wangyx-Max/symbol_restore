from idc import *
from perfect_match import PerfectMatch, MultipleMatch, FuzzyMatch

t0 = time.time()
sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
sym_db = "libcpp_empty_test.sqlite"
pm = PerfectMatch(sqlite_db, sym_db)
pm.do_perfect_match('test')
pm.do_slow_match('test')
mm = MultipleMatch(sqlite_db, sym_db)
mm.do_multiple_match()
fm = FuzzyMatch(sqlite_db, sym_db)
fm.do_fuzzy_match()
time_elapsed = time.time() - t0
print('Total time in {:.0f}m {:.0f}s'.format(
    time_elapsed // 60, time_elapsed % 60))