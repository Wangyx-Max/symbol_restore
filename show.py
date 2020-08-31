from sql_opt import *
from idc import *
from idautils import *
from idaapi import *
import idaapi
import ida_graph
import ida_kernwin
import ida_moves


try:
    if idaapi.IDA_SDK_VERSION < 690:
        # In versions prior to IDA 6.9 PySide is used...
        from PySide import QtGui
        QtWidgets = QtGui
        is_pyqt5 = False
    else:
        # ...while in IDA 6.9, they switched to PyQt5
        from PyQt5 import QtCore, QtGui, QtWidgets
        is_pyqt5 = True
except ImportError:
    pass


class Rename:
    def __init__(self, bin_name, src_name=None):
        self.bin_name = bin_name
        self.src_name = src_name
        pass

    def rename(self):
        sql_op = SqlOperate(self.bin_name)
        rows = sql_op.read_results()
        for row in rows:
            if str(row[1]).startswith('sub_') or str(row[1]).startswith('nullsub_'):
                MakeName(int(row[0]), 'wyx_' + str(row[3]).replace('`', '').replace('-', ''))

    def show_des(self):
        sql_op = SqlOperate(self.bin_name)
        rows = sql_op.read_results_des()
        for row in rows:
            print row[1] + '->' + row[0]


class SourceCodeViewer(object):
    class SourceCodeViewerUI(idaapi.simplecustviewer_t):
        def __init__(self, title):
            idaapi.simplecustviewer_t.__init__(self)
            self.ea = None
            self.query = None
            self.idx = None
            self.targets = None
            self.title = title
            self.Create(title)
            idaapi.set_code_viewer_is_source(idaapi.create_code_viewer(self.GetWidget(), 0x4))

        def set_user_data(self, ea, targets):
            self.ea = idaapi.get_func(ea).start_ea
            self.query = idaapi.get_func_name(ea)
            self.targets = targets
            self._repaint()

        def _repaint(self):
            self.ClearLines()
            for i, target in enumerate(self.targets):
                for line in SourceCodeViewer.source_code_comment(self.query, target, i).split("\n"):
                    # print line
                    self.AddLine(idaapi.COLSTR(line, idaapi.SCOLOR_RPTCMT))
                for line in SourceCodeViewer.source_code_body(target):
                    self.AddLine(str(line))
            self.Refresh()

        def show_pesudo(self):
            widget = idaapi.get_current_widget()
            if idaapi.get_widget_title(widget) != self.title:
                if idaapi.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
                    pseudo_view = idaapi.open_pseudocode(self.ea, 1)
                    pseudo_view.refresh_view(1)
                    widget = pseudo_view.toplevel
                pseudo_title = idaapi.get_widget_title(widget)

                idaapi.display_widget(self.GetWidget(),
                                      idaapi.PluginForm.WOPN_DP_TAB | idaapi.PluginForm.WOPN_RESTORE)
                idaapi.set_dock_pos(self.title, pseudo_title, idaapi.DP_RIGHT)

        def show_asm(self):
            jumpto(self.ea)
            widget = idaapi.get_current_widget()
            if idaapi.get_widget_title(widget) != self.title:
                jumpto(self.ea)
                if idaapi.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
                    widget = ida_kernwin.open_disasm_window("A")

                title = idaapi.get_widget_title(widget)

                idaapi.display_widget(self.GetWidget(),
                                      idaapi.PluginForm.WOPN_DP_TAB | idaapi.PluginForm.WOPN_RESTORE)
                idaapi.set_dock_pos(self.title, title, idaapi.DP_RIGHT)

        def OnKeydown(self, vkey, shift):
            if shift == 0 and vkey == ord("K"):
                self.idx = (self.idx + len(self.targets) - 1) % len(self.targets)
                self._repaint()
            elif shift == 0 and vkey == ord("J"):
                self.idx = (self.idx + 1) % len(self.targets)
                self._repaint()

    @staticmethod
    def source_code_comment(query, func, i):
        return """/*
    query:  {}
    target[{}]: {}
    description: {}
*/\n""".format(query, i, func[1], func[3])

    @staticmethod
    def source_code_body(func):
        body = func[2].split("\n")
        return filter(lambda l: not l.lstrip().startswith('#'), body)

    def __init__(self, title):
        self.view = None  # type: SourceCodeViewer.SourceCodeViewerUI
        self.title = title

    def is_visible(self):
        return self.view and self.view.GetWidget()

    def set_user_data(self, ea, targets, code_type):
        if not self.is_visible():
            self.view = SourceCodeViewer.SourceCodeViewerUI(self.title)
        self.view.set_user_data(ea, targets)
        if code_type == 'asm':
            self.view.show_asm()
        if code_type == 'pseudo':
            self.view.show_pesudo()

    def get_current_info(self):
        return self.view.ea, \
               self.view.targets[self.view.idx]['function']['name'], \
               self.view.targets[self.view.idx]['score']


class MyChoose(Choose2):
    def __init__(self, title, bin_name, src_name, rows):
        if title.startswith("Fuzzy"):
            Choose2.__init__(
                self,
                title,
                [["Org_Name", 10],
                 ["Symbol_Name", 18],
                 ["Ratio", 5],
                 ["Description", 20], Choose2.CH_MULTI])
        else:
            Choose2.__init__(
                self,
                title,
                [["Address", 8],
                 ["Org_Name", 10],
                 ["Symbol_Name", 20],
                 ["Description", 20], Choose2.CH_MULTI])
        self.items = []
        self.icon = 41
        self.cview = SourceCodeViewer('Matched Functions Code')
        self.bin_name = bin_name
        self.src_name = src_name
        self.cmd_show_asm = None
        self.cmd_show_pseudo = None
        self.rows = rows

    def OnInit(self):
        for row in self.rows:
            if str(row[1]).startswith('sub_') or str(row[1]).startswith('nullsub_'):
                x = int(row[0])
                self.items.append([hex(x), get_func_name(x), str(row[3]).replace('`', ''), str(row[4]), x, str(row[2])])
        # print len(self.items)
        return True

    def show(self):
        t = self.Show()
        if t < 0:
            return False
        self.cmd_show_pseudo = self.AddCommand('show pseudocode')
        self.cmd_show_asm = self.AddCommand('show assembly')

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnDeleteLine(self, n):
        ea = self.items[n][4]
        idc.del_func(ea)
        return (idaapi.Choose.ALL_CHANGED, n)

    def OnSelectLine(self, n):
        try:
            jump_ea = int(self.items[n][0], 16)
            # Only jump for valid addresses
            if isEnabled(jump_ea):
                jumpto(jump_ea)
        except:
            print "OnSelectLine", sys.exc_info()[1]
        return (idaapi.Choose.NOTHING_CHANGED, )

    def OnRefresh(self, n):
        self.OnInit()
        # try to preserve the cursor
        return [idaapi.Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        print("closed ", self.title)

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.cmd_show_pseudo:
            self.show_pseudo(n)
        if cmd_id == self.cmd_show_asm:
            self.show_asm(n)

    def show_code(self, n, sql, ct):
        sql_op = SqlOperate(self.bin_name)
        conn, cur = sql_op.attach(self.src_name)
        cur.execute(sql % str(self.items[n][4]))
        targets = cur.fetchall()
        cur.close()
        self.cview.set_user_data(self.items[n][4], targets, ct)


class PerfectChoose(MyChoose):
    def __init__(self, title, bin_name, src_name, rows):
        MyChoose.__init__(self, title, bin_name, src_name, rows)

    def show_pseudo(self, n):
        sql = """select distinct id, name, pseudocode, description from diff.functions, results
            where address in (select src_address from results where bin_address = %s)
            and address = src_address
        """
        self.show_code(n, sql, 'pseudo')

    def show_asm(self, n):
        sql = """select distinct id, name, assembly, description from diff.functions, results
            where address in (select src_address from results where bin_address = %s)
            and address = src_address
        """
        self.show_code(n, sql, 'asm')


class MultiChoose(MyChoose):
    def __init__(self, title, bin_name, src_name, rows):
        MyChoose.__init__(self, title, bin_name, src_name, rows)

    def show_asm(self, n):
        sql = """select distinct id, name, assembly, description from diff.functions, results_multi
            where address in (select src_address from results_multi where bin_address = %s)
            and address = src_address
        """
        self.show_code(n, sql, 'asm')

    def show_pseudo(self, n):
        sql = """select distinct id, name, pseudocode, description from diff.functions, results_multi
            where address in (select src_address from results_multi where bin_address = %s)
            and address = src_address
        """
        self.show_code(n, sql, 'pseudo')


class FuzzyChoose(MyChoose):
    def OnInit(self):
        for row in self.rows:
            if str(row[2]).startswith('sub_') or str(row[2]).startswith('nullsub_'):
                x = int(row[1])
                self.items.append([get_func_name(x), str(row[4]).replace('`', ''),
                                   str(row[5]), str(row[6]), x, str(row[2])])
        # print len(self.items)
        return True

    def show_asm(self, n):
        sql = """select distinct f.id, name, assembly, description from diff.functions f, results_fuzzy
            where address in (select src_address from results_fuzzy where bin_address = %s)
            and address = src_address
        """
        self.show_code(n, sql, 'asm')

    def show_pseudo(self, n):
        sql = """select distinct f.id, name, pseudocode, description from diff.functions f, results_fuzzy
            where address in (select src_address from results_fuzzy where bin_address = %s)
            and address = src_address
        """
        self.show_code(n, sql, 'pseudo')


def show_all_results(bin_name, src_name, title='Perfect Match'):
    sql_op = SqlOperate(bin_name)
    if title.startswith('Perfect'):
        rows = sql_op.read_results()
        CChoose = PerfectChoose
    elif title.startswith('Multiple'):
        rows = sql_op.read_results_multi('show')
        CChoose = MultiChoose
    else:
        rows = sql_op.read_results_fuzzy()
        CChoose = FuzzyChoose

    c = CChoose(title, bin_name, src_name, rows)
    c.show()



