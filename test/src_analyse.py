import time
from perfect_match import AnalyseFunction

t0 = time.time()
sqlite_db = "diff.sqlite"
af = AnalyseFunction(sqlite_db)
af.analyse_symbol()
time_elapsed = time.time() - t0
print('Total time in {:.0f}m {:.0f}s'.format(
    time_elapsed // 60, time_elapsed % 60))
