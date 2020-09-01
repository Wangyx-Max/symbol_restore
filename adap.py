"""
interactive program
open this file in IDA Pro
"""
from adap_match import *
from adap_show import *


class busy_form_t(ida_kernwin.Form):

    class test_chooser_t(ida_kernwin.Choose):
        """
        A simple chooser to be used as an embedded chooser
        """
        def __init__(self, title, nb=5, flags=ida_kernwin.Choose.CH_MULTI):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["Address", 10],
                    ["Name", 30]
                ],
                flags=flags,
                embedded=True,
                width=30,
                height=6)
            self.items = [ [str(x), "func_%04d" % x] for x in range(nb + 1) ]
            self.icon = 5

        def OnGetLine(self, n):
            print("getline %d" % n)
            return self.items[n]

        def OnGetSize(self):
            n = len(self.items)
            print("getsize -> %d" % n)
            return n

    def __init__(self):
        self.invert = False
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""
SQLite databases:
<#Select a file to export the current IDA database to SQLite format#Export IDA database to SQLite  :{iFileSave}>
<#Select the SQLite database to diff against                       #SQLite database to diff against:{iFileOpen}>

<##Match boxes##Perfect Match:{rPerfectMatch}>
<Slow Match:{rSlowMatch}>
<Multiple Match:{rMultiMatch}>              
<Fuzzy Match:{rFuzzyMatch}>{cGroup1}> 

<##Show boxes##Show Results:{rShowResults}>
<Save Results:{rSaveResults}>{cGroup2}>

""", {
            'iFileOpen': F.FileInput(open=True),
            'iFileSave': F.FileInput(save=True),
            'cGroup1': F.ChkGroupControl(("rPerfectMatch", "rSlowMatch", "rMultiMatch", "rFuzzyMatch")),
            'cGroup2': F.RadGroupControl(("rShowResults", "rSaveResults"))
        })

    @staticmethod
    def compile_and_fiddle_with_fields():
        f = busy_form_t()
        f, args = f.Compile()
        print(args[0])
        print(args[1:])
        f.rPerfectMatch.checked = True
        f.rMultiMatch.checked = False
        f.rFuzzyMatch.checked = False
        print(hex(f.cGroup1.value))

        f.Free()

    @staticmethod
    def test():
        f = busy_form_t()

        # Compile (in order to populate the controls)
        f.Compile()

        f.iFileSave.value = os.path.splitext(idc.GetIdbPath())[0] + ".sqlite"
        f.rPerfectMatch.checked = True
        f.rSlowMatch.checked = False
        f.rMultiMatch.checked = False
        f.rFuzzyMatch.checked = False
        f.rSaveResults.selected = True

        # Execute the form
        ok = f.Execute()
        if ok == 1:
            if f.iFileOpen.value == "":
                t0 = time.time()
                af = AnalyseFunction(f.iFileSave.value)
                if f.rSlowMatch.checked is True:
                    af.analyse_symbol_slow()
                else:
                    af.analyse_symbol()
                time_elapsed = time.time() - t0
                print('Total time in {:.0f}m {:.0f}s'.format(
                    time_elapsed // 60, time_elapsed % 60))
            else:
                t0 = time.time()
                pm = PerfectMatch(f.iFileSave.value, f.iFileOpen.value)
                if f.rPerfectMatch.checked is True:
                    pm.do_perfect_match()
                else:
                    pm.do_perfect_match('init')
                if f.rSlowMatch.checked is True:
                    if f.rPerfectMatch.checked is True:
                        pm.do_slow_match()
                    else:
                        pm.do_slow_match('init')
                if f.rMultiMatch.checked is True:
                    mm = MultipleMatch(f.iFileSave.value, f.iFileOpen.value)
                    mm.do_multiple_match()
                if f.rFuzzyMatch.checked is True and f.rSlowMatch.checked is True:
                    fm = FuzzyMatch(f.iFileSave.value, f.iFileOpen.value)
                    fm.do_fuzzy_match()
                time_elapsed = time.time() - t0
                print('Total time in {:.0f}m {:.0f}s'.format(
                    time_elapsed // 60, time_elapsed % 60))
            if f.rShowResults.selected is True:
                show_all_results(f.iFileSave.value, f.iFileOpen.value)
                show_all_results(f.iFileSave.value, f.iFileOpen.value, 'Multiple Match')
                show_all_results(f.iFileSave.value, f.iFileOpen.value, 'Fuzzy Match')

        # Dispose the form
        f.Free()


busy_form_t.test()