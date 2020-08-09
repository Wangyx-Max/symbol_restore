from sql_opt import *
from perfect_match import *
from idc import *
from idautils import *
from idaapi import *

"""
name = "C:\\Users\\Admin\\Desktop\\data7\\libcpp_tests_noSymbol.sqlite"
sql = "update or ignore functions set numbers2 = ?, numbers2_count = ? where address = ?"
sql_op = SqlOperate(name)
conn, cur = sql_op.connect()
af = AnalyseFunction(name)
for f in list(Functions(MinEA(), MaxEA())):
    if af.func_check(f) is False:
        continue
    func = get_func(f)
    nums2 = []
    instructions = 0
    for line in list(Heads(func.startEA, func.endEA)):
        mnem = GetMnem(line)
        instructions += 1
        if mnem != '' and GetOpType(line, 1):
            nums2.append(GetOperandValue(line, 1))

    if instructions > 5:
        nums2 = []
    props = af.create_sql_props((nums2, len(nums2), f))
    cur.execute(sql, props)
    conn.commit()
cur.close()
"""

name = "C:\\Users\\Admin\\Desktop\\data7\\diff.sqlite"
af = AnalyseFunction(name)
af.save_constants(list(Functions(MinEA(), MaxEA())))
