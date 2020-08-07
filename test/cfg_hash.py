from idaapi import *
from idautils import *
from idc import *

import json
import decimal
import sqlite3
import time

# Different type of basic blocks (graph nodes).
NODE_ENTRY = 2
NODE_EXIT = 3
NODE_NORMAL = 5

#
# NOTE: In the current implementation (Nov-2018) all edges are considered as if
# they were conditional. Keep reading...
#
EDGE_IN_CONDITIONAL = 7
EDGE_OUT_CONDITIONAL = 11

#
# Reserved but unused because, probably, it doesn't make sense when comparing
# multiple different architectures.
#
#EDGE_IN_UNCONDITIONAL = 13
#EDGE_OUT_UNCONDITIONAL = 17

#
# The following are feature types that aren't applied at basic block but rather
# at function level. The idea is that if we do at function level we will have no
# problems finding the same function that was re-ordered because of some crazy
# code a different compiler decided to create (i.e., resilient to reordering).
#
FEATURE_LOOP = 19
FEATURE_CALL = 23
FEATURE_DATA_REFS = 29
FEATURE_CALL_REF = 31
FEATURE_STRONGLY_CONNECTED = 37
FEATURE_FUNC_NO_RET = 41
FEATURE_FUNC_LIB = 43
FEATURE_FUNC_THUNK = 47

class CFGHash:
    def __init__(self):
       pass

    def strongly_connected_components(self, graph):
        """ Find the strongly connected components in a graph using
            Tarjan's algorithm.
            
            graph should be a dictionary mapping node names to
            lists of successor nodes.
            """
        
        result = [ ]
        stack = [ ]
        low = { }
            
        def visit(node):
            if node in low: return

            num = len(low)
            low[node] = num
            stack_pos = len(stack)
            stack.append(node)
            
            for successor in graph[node]:
                visit(successor)
                low[node] = min(low[node], low[successor])
            
            if num == low[node]:
                component = tuple(stack[stack_pos:])
                del stack[stack_pos:]
                result.append(component)
                for item in component:
                    low[item] = len(graph)
        
        for node in graph:
            visit(node)
        
        return result

    def topological_sort(self, graph):
        count = { }
        for node in graph:
            count[node] = 0
        for node in graph:
            for successor in graph[node]:
                count[successor] += 1

        ready = [ node for node in graph if count[node] == 0 ]
        
        result = [ ]
        while ready:
            node = ready.pop(-1)
            result.append(node)
            
            for successor in graph[node]:
                count[successor] -= 1
                if count[successor] == 0:
                    ready.append(successor)
        
        return result

    def robust_topological_sort(self, graph):
        """ First identify strongly connected components,
            then perform a topological sort on these components. """

        components = self.strongly_connected_components(graph)

        node_component = { }
        for component in components:
            for node in component:
                node_component[node] = component

        component_graph = { }
        for component in components:
            component_graph[component] = [ ]
        for node in graph:
            node_c = node_component[node]
            for successor in graph[node]:
                successor_c = node_component[successor]
                if node_c != successor_c:
                    component_graph[node_c].append(successor_c) 

        return self.topological_sort(component_graph)

    def func_check(self, f):
        flags = GetFunctionFlags(int(f))

        if flags & FUNC_LIB or flags & FUNC_THUNK or flags == -1:
            return False

        func = get_func(f)
        if not func:
            print("Cannot get a function object for 0x%x" % f)
            return False
        return True

    def md_index(self, func):
        self.func_check(func)
        image_base = get_imagebase()
        nodes = 0
        bb_topological = {}
        bb_topo_num = {}
        bb_relations = {}
        bb_degree = {}
        bb_edges = []
        f = func
        func = get_func(func)
        flow = FlowChart(func)
        hash = 1
        for block in flow:
            if block.endEA == 0 or block.endEA == BADADDR:
                print("0x%08x: Skipping bad basic block" % f)
                continue
            
            nodes += 1

            succs = list(block.succs())
            preds = list(block.preds())

            hash *= self.get_node_value(len(succs), len(preds))
            hash *= self.get_edges_value(block, succs, preds)
            
            block_ea = block.startEA - image_base
            idx = len(bb_topological)
            bb_topological[idx] = []
            bb_topo_num[block_ea] = idx

            bb_relations[block_ea] = []
            
            if block_ea not in bb_degree:
                bb_degree[block_ea] = [0, 0]

            for ea in list(Heads(block.startEA, block.endEA)):

                if is_call_insn(ea):
                    hash *= FEATURE_CALL

                l = list(DataRefsFrom(ea))
                if len(l) > 0:
                    hash *= FEATURE_DATA_REFS

                for xref in CodeRefsFrom(ea, 0):
                    tmp_func = get_func(xref)
                    if tmp_func is None or tmp_func.startEA != func.startEA:
                        hash *= FEATURE_CALL_REF
            
            for succ_block in block.succs():
                if succ_block.endEA == 0:
                    continue
            
                succ_base = succ_block.startEA - image_base
                bb_relations[block_ea].append(succ_base)
                bb_degree[block_ea][1] += 1
                bb_edges.append((block_ea, succ_base))
                if succ_base not in bb_degree:
                    bb_degree[succ_base] = [0, 0]
                bb_degree[succ_base][0] += 1

            for pred_block in block.preds():
                if pred_block.endEA == 0:
                    continue
            
                try:
                    bb_relations[pred_block.startEA - image_base].append(block.startEA - image_base)
                except KeyError:
                    bb_relations[pred_block.startEA - image_base] = [block.startEA - image_base]

        try:
            strongly_connected = self.strongly_connected_components(bb_relations)
            # ...and get the number of loops out of it
            for sc in strongly_connected:
                if len(sc) > 1:
                    hash *= FEATURE_LOOP
                else:
                    if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
                        hash *= FEATURE_LOOP

            # And, also, use the number of strongly connected components
            # to calculate another part of the hash.
            hash *= (FEATURE_STRONGLY_CONNECTED ** len(strongly_connected))
        except:
            print("Exception:", str(sys.exc_info()[1]))

        flags = GetFunctionFlags(f)
        if flags & FUNC_NORET:
            hash *= FEATURE_FUNC_NO_RET
        if flags & FUNC_LIB:
            hash *= FEATURE_FUNC_LIB
        if flags & FUNC_THUNK:
            hash *= FEATURE_FUNC_THUNK

        for block in flow:
            if block.endEA == 0:
                continue
            block_ea = block.startEA - image_base
            for succ_block in block.succs():
                if succ_block.endEA == 0:
                    continue
                succ_base = succ_block.startEA - image_base
                bb_topological[bb_topo_num[block_ea]].append(bb_topo_num[succ_base])

        try:
            bb_topological_sorted = self.robust_topological_sort(bb_topological)
            bb_topological = json.dumps(bb_topological_sorted)
        except:
            bb_topological = None
        # print bb_topological_sorted
        md_index = 0
        if bb_topological:
            bb_topo_order = {}
            for i, scc in enumerate(bb_topological_sorted):
                for bb in scc:
                    bb_topo_order[bb] = i
            tuples = []
            # print bb_topo_order
            for src, dst in bb_edges:
                tuples.append((
                    bb_topo_order[bb_topo_num[src]],
                    bb_degree[src][0],
                    bb_degree[src][1],
                    bb_degree[dst][0],
                    bb_degree[dst][1],))
            # print bb_topo_order[bb_topo_num[src]], bb_degree[src][0], bb_degree[src][1], bb_degree[dst][0], bb_degree[dst][1]
            rt2, rt3, rt5, rt7 = (decimal.Decimal(p).sqrt() for p in (2, 3, 5, 7))
            emb_tuples = (sum((z0, z1 * rt2, z2 * rt3, z3 * rt5, z4 * rt7))
                    for z0, z1, z2, z3, z4 in tuples)
            md_index = sum((1 / emb_t.sqrt() for emb_t in emb_tuples))
            md_index = str(md_index)
        
        return hash, md_index, nodes

    def get_node_value(self, succs, preds):
        """ Return a set of prime numbers corresponding to the characteristics of the node. """
        ret = 1
        if succs == 0:
            ret *= NODE_ENTRY
    
        if preds == 0:
            ret *= NODE_EXIT

        ret *= NODE_NORMAL
        return ret

    def get_edges_value(self, bb, succs, preds):
        ret = 1
        for _ in succs:
            ret *= EDGE_OUT_CONDITIONAL

        for _ in preds:
            ret *= EDGE_IN_CONDITIONAL

        return ret

    def md_index_match(self):
        t0 = time.time()
        for func in self.functions:
            md_index, nodes = self.md_index(func)
            kgh_hash = self.kgh_hash(func)
            props = [md_index, kgh_hash, str(func)]
            sql = """update or ignore functions set md_index = ?, kgh_hash = ?
                where address = ?
                """
            self.cur.execute(sql , props)
            self.conn.commit()
      

        self.cur.execute('attach "%s" as diff' % self.src_name)
        self.conn.commit()

        sql = """
                select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        'CFG Hash Match' description,
                        f.md_index, f.kgh_hash
                from functions f,
                     diff.functions df,
                    (select kgh_hash
                      from main.functions
                      where kgh_hash != 0
                      group by kgh_hash
                      having count(*) == 1
                    ) shared_hashes,
                    (select md_index
                      from main.functions
                      where md_index != 0
                      group by md_index
                      having count(*) == 1
                    ) shared_mds
                where f.md_index = df.md_index
                and f.md_index = shared_mds.md_index
                and f.kgh_hash = df.kgh_hash
                and f.kgh_hash = shared_hashes.kgh_hash
                and f.nodes > 10
            """
        sql_insert = """
                insert or ignore into results (
                    bin_address, bin_name, src_name, description) 
                    values (?, ?, ?, ?)"""
        
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        for row in rows:
            self.bin_matched.add(str(row[0]))
            self.src_matched.add(str(row[2]))
            props = [str(row[0]), str(row[1]), str(row[3]), 'CFG Hash Match']
            # print props
            self.cur.execute(sql_insert, props)
            self.conn.commit()
        print len(rows)

        time_elapsed = time.time() - t0
        print('Training complete in {:.0f}m {:.0f}s'.format(
            time_elapsed // 60, time_elapsed % 60))
