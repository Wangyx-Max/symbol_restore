"""
interactive program
open this file in IDA Pro
"""
from adap_match import *
from adap_show import *


class Options:
    def __init__(self, **kwargs):
        sqlite_db = os.path.splitext(GetIdbPath())[0] + ".sqlite"
        self.file_out = kwargs.get('file_out', sqlite_db)
        self.file_in = kwargs.get('file_in', '')
        self.perfect_match = kwargs.get('perfect_match', True)
        self.slow_match = kwargs.get('slow_match', False)
        self.multi_match = kwargs.get('multi_match', False)
        self.fuzzy_match = kwargs.get('fuzzy_match', False)
        self.show = kwargs.get('show', True)
        self.only_show = kwargs.get('only_show', False)


class ExporterSetup(ida_kernwin.Form):
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
<Only Show Results:{rOnlyShowResults}>
<Save Results:{rSaveResults}>{cGroup2}>

""", {
                'iFileOpen': F.FileInput(open=True),
                'iFileSave': F.FileInput(save=True),
                'cGroup1': F.ChkGroupControl(("rPerfectMatch", "rSlowMatch", "rMultiMatch", "rFuzzyMatch")),
                'cGroup2': F.RadGroupControl(("rShowResults", "rOnlyShowResults", "rSaveResults"))
            })

    def set_options(self, opts):
        self.iFileSave.value = opts.file_out
        self.iFileOpen.value = opts.file_in
        self.rPerfectMatch.checked = opts.perfect_match
        self.rSlowMatch.checked = opts.slow_match
        self.rMultiMatch.checked = opts.multi_match
        self.rFuzzyMatch.checked = opts.fuzzy_match
        self.rOnlyShowResults.selected = opts.only_show
        self.rShowResults.selected = opts.show

    def get_options(self):
        opts = dict(
            file_out=self.iFileSave.value,
            file_in=self.iFileOpen.value,
            perfect_match=self.rPerfectMatch.checked,
            slow_match=self.rSlowMatch.checked,
            multi_match=self.rMultiMatch.checked,
            fuzzy_match=self.rFuzzyMatch.checked,
            only_show=self.rOnlyShowResults.selected,
            show=self.rShowResults.selected
        )
        return Options(**opts)


def diff_or_match(**options):
    total_functions = len(list(Functions()))
    if GetIdbPath() == "" or total_functions == 0:
        return
    opts = Options(**options)
    x = ExporterSetup()
    x.Compile()
    x.set_options(opts)

    if not x.Execute():
        return

    opts = x.get_options()
    # print opts.file_in
    show_wait_box("Start Running ... ")
    if opts.file_out == opts.file_in:
        return
    elif opts.file_in == "":
        af = AnalyseFunction(opts.file_out)
        if opts.slow_match is True:
            af.analyse_symbol_slow()
        else:
            af.analyse_symbol()
    elif opts.only_show is True:
        show_all_results(opts.file_out, opts.file_in)
        if opts.multi_match is True:
            show_all_results(opts.file_out, opts.file_in, 'Multiple Match')
        if opts.fuzzy_match is True:
            show_all_results(opts.file_out, opts.file_in, 'Fuzzy Match')
    else:
        pm = PerfectMatch(opts.file_out, opts.file_in)
        if opts.perfect_match is True:
            pm.do_perfect_match()
            if opts.slow_match is True:
                pm.do_slow_match()
        else:
            pm.do_perfect_match('init')
            if opts.slow_match is True:
                pm.do_slow_match('init')
        if opts.multi_match is True:
            mm = MultipleMatch(opts.file_out, opts.file_in)
            mm.do_multiple_match()
        if opts.fuzzy_match is True and opts.slow_match is True:
            fm = FuzzyMatch(opts.file_out, opts.file_in)
            fm.do_fuzzy_match()
        if opts.show is True:
            show_all_results(opts.file_out, opts.file_in)
            if opts.multi_match is True:
                show_all_results(opts.file_out, opts.file_in, 'Multiple Match')
            if opts.fuzzy_match is True:
                show_all_results(opts.file_out, opts.file_in, 'Fuzzy Match')


def main():
    diff_or_match()
    hide_wait_box()


main()
