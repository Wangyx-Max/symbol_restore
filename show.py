from sql_opt import *
from idc import *
from idautils import *
from idaapi import *

class show:
    def __init__(self, bin_name, src_name=None):
        self.bin_name = bin_name
        self.src_name = src_name
        pass

    def rename(self):
        sql_op = SqlOperate(self.bin_name)
        rows = sql_op.read_results()
        for row in rows:
            if str(row[1]).startswith('sub_') or str(row[1]).startswith('nullsub_'):
                MakeName(int(row[0]), 'wyx_' + str(row[3]).replace('`', ''))

    def show_des(self):
        sql_op = SqlOperate(self.bin_name)
        rows = sql_op.read_results_des()
        for row in rows:
            print row[1] + '->' + row[0]


bin_name = os.path.splitext(GetIdbPath())[0] + ".sqlite"
s = show(bin_name)
s.rename()
s.show_des()
