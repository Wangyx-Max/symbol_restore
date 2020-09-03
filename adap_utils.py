import base64
import decimal
import json
import random
from StringIO import StringIO
from difflib import SequenceMatcher
from itertools import imap

import idaapi
from idaapi import *
from idautils import *
from idc import *

#---------------------------------------------------------------------------
def primesblow(N):
    # http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n-in-python/3035188#3035188
    # """ Input N>=6, Returns a list of primes, 2 <= p < N """
    correction = N % 6 > 1
    N = {0: N, 1: N - 1, 2: N + 4, 3: N + 3, 4: N + 2, 5: N + 1}[N % 6]
    sieve = [True] * (N // 3)
    sieve[0] = False
    for i in range(long(N ** .5) // 3 + 1):
        if sieve[i]:
            k = (3 * i + 1) | 1
            sieve[k * k // 3::2 * k] = [False] * ((N // 6 - (k * k) // 6 - 1) // k + 1)
            sieve[(k * k + 4 * k - 2 * k * (i % 2)) // 3::2 * k] = [False] * (
                    (N // 6 - (k * k + 4 * k - 2 * k * (i % 2)) // 6 - 1) // k + 1)
    return [2, 3] + [(3 * i + 1) | 1 for i in range(1, N // 3 - correction) if sieve[i]]


def isprime(n, precision=7):
    # http://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Algorithm_and_running_time
    smallprimeset = set(primesblow(100000))
    _smallprimeset = 100000
    if n == 1 or n % 2 == 0:
        return False
    elif n < 1:
        raise ValueError("Out of bounds, first argument must be > 0")
    elif n < _smallprimeset:
        return n in smallprimeset

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for repeat in range(precision):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for r in range(s - 1):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False
    return True


def gcd(a, b):
    if a == b:
        return a
    while b > 0:
        a, b = b, a % b
    return a


def pollard_brent(n):
    if n % 2 == 0: return 2
    if n % 3 == 0: return 3

    y, c, m = random.randint(1, n-1), random.randint(1, n-1), random.randint(1, n-1)
    g, r, q = 1, 1, 1
    while g == 1:
        x = y
        for i in range(r):
            y = (pow(y, 2, n) + c) % n

        k = 0
        while k < r and g==1:
            ys = y
            for i in range(min(m, r-k)):
                y = (pow(y, 2, n) + c) % n
                q = q * abs(x-y) % n
            g = gcd(q, n)
            k += m
        r *= 2
    if g == n:
        while True:
            ys = (pow(ys, 2, n) + c) % n
            g = gcd(abs(x - ys), n)
            if g > 1:
                break

    return g


def prime_factors(n, sort=False):
    smallprimes = primesblow(10000)
    # might seem low, but 10000*10000 = 100000000, so this will fully factor every composite < 100000000

    factors = []
    limit = long(n ** decimal.Decimal(.5)) + 1
    for checker in smallprimes:
        if checker > limit:
            break
        while n % checker == 0:
            factors.append(checker)
            n //= checker
            limit = long(n ** decimal.Decimal(.5)) + 1
            if checker > limit:
                break

    if n < 2:
        return factors

    while n > 1:
        if isprime(n):
            factors.append(n)
            break
        factor = pollard_brent(n)
        # trial division did not fully factor, switch to pollard-brent
        factors.extend(prime_factors(factor))
        # recurse to factor the not necessarily prime factor returned by pollard-brent
        n //= factor

    if sort:
        factors.sort()

    return factors


def factorization(n):
    factors = {}
    for p1 in prime_factors(n):
        try:
            factors[p1] += 1
        except KeyError:
            factors[p1] = 1
    return factors


def _difference(num1, num2):
    FACTORS_CACHE = {}
    nums = [num1, num2]
    s = []
    for num in nums:
        if FACTORS_CACHE.has_key(num):
            x = FACTORS_CACHE[num]
        else:
            x = factorization(long(num))
            FACTORS_CACHE[num] = x
        s.append(x)

    diffs = {}
    for x in s[0].keys():
        if x in s[1].keys():
            if s[0][x] != s[1][x]:
                diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
        else:
            diffs[x] = s[0][x]

    for x in s[1].keys():
        if x in s[0].keys():
            if s[1][x] != s[0][x]:
                diffs[x] = max(s[0][x], s[1][x]) - min(s[0][x], s[1][x])
        else:
            diffs[x] = s[1][x]

    return diffs, s


def difference_ratio(num1, num2):
    diffs, s = _difference(num1, num2)
    total = max(sum(s[0].values()), sum(s[1].values()))
    return 1 - (sum(diffs.values()) * 1. / total)


def quick_ratio(buf1, buf2):
    try:
        if buf1 is None or buf2 is None or buf1 == "" or buf1 == "":
            return 0
        s = SequenceMatcher(None, buf1.split("\n"), buf2.split("\n"))
        return s.quick_ratio()
    except:
        print("quick_ratio:", str(sys.exc_info()[1]))
        return 0


def measure_bits_variance(const):
    variance = 0
    level = 1
    # print const
    const = bin(const)[2:]
    while const.count('0') != len(const) and level < 4:
        cur_const = '1' if const[0] != const[-1] else '0'
        last_bit = const[0]
        for bit in const[1:]:
            cur_const += '1' if bit != last_bit else '0'
            last_bit = bit
        const = cur_const
        variance += level * abs(32 * 0.5 - abs(cur_const.count('1') - 3 * 0.5))
        level += 1
    return variance


def measure_bits_entropy(const):
    # we only work on unsigned values
    if const < 0:
        const += 2 ** 32
    # variance score (embeds inside it the number of bits)
    return measure_bits_variance(const) * 1.0 / (32 / 2)


def count_set_bits(const):
    # we only work on unsigned values
    if const < 0:
        const += 2 ** 32
    # simply count them
    return bin(const).count('1')


def rank_nums(const):
    score = measure_bits_entropy(const)
    score = score * score
    if const in [0xFFFFFFFF, -1]:
        score += 4
    if count_set_bits(const) == 1:
        score += 6
    return score


def compare_callee(src_addr, bin_addr, cur):
    score = 0.0
    sql_src = """select callee_address from diff.callers where caller_address = %s"""
    sql_bin = """select callee_address from callers where caller_address = %s"""
    sql_res_src = """select bin_address from results where src_address = %s
               union select bin_address from results_multi where src_address = %s"""
    sql_res_bin = """select src_address from results where bin_address = %s
               union select bin_address from results_multi where src_address = %s"""
    cur.execute(sql_src % src_addr)
    src_callees = cur.fetchall()
    cur.execute(sql_bin % bin_addr)
    bin_callees = cur.fetchall()
    # print src_callees, bin_callees
    for src_callee in src_callees:
        cur.execute(sql_res_src % (str(src_callee[0]), str(src_callee[0])))
        # print sql_res_src % str(src_callee[0])
        row = cur.fetchone()
        if row is not None and str(row[0]) in bin_callees:
            score += 5
        else:
            score -= 3
    for bin_callee in bin_callees:
        cur.execute(sql_res_bin % (str(bin_callee[0]), str(bin_callee[0])))
        # print sql_res_bin % str(bin_callee[0])
        row = cur.fetchone()
        if row is not None and str(row[0]) in src_callees:
            score += 5
        else:
            score -= 3
    if len(src_callees) == len(bin_callees) and len(src_callees) > 0:
        score += 5

    return score


def compare_numbers(bin_nums, src_nums):
    score = 0
    # earn points by ranking the consts in the intersection
    for num in set(src_nums).intersection(bin_nums):
        score += rank_nums(num)
    # deduce points by ranking the consts in the symmetric difference
    for num in set(src_nums).difference(bin_nums):
        score -= rank_nums(num)
    for num in set(bin_nums).difference(src_nums):
        score -= rank_nums(num)
    # give a boost for a perfect match
    if len(src_nums) > 0 and src_nums == bin_nums:
        score += 3
    return score


def compare_consts(bin_consts, src_consts):
    score = 0
    for const in set(src_consts).intersection(bin_consts):
        score += len(const)
    for const in set(src_consts).difference(bin_consts):
        score -= len(const)
    for const in set(bin_consts).difference(src_consts):
        score -= len(const)
    if len(src_consts) > 0 and bin_consts == src_consts:
        score += 3
    return score


def check_ratio(pseudo1, pseudo2, asm1, asm2, ast1, ast2, md1, md2):
    fratio = quick_ratio
    decimal_values = "{0:.2f}"
    v1 = 0
    if (pseudo1 is not None) and (pseudo2 is not None) and pseudo1 != "" and pseudo2 != "":
        if pseudo1 != "" or pseudo2 != "":
            v1 = fratio(pseudo1, pseudo2)
            v1 = float(decimal_values.format(v1))

    v2 = fratio(asm1, asm2)
    v2 = float(decimal_values.format(v2))

    v3 = 0.0
    if ast1 is not None and (ast2 is not None) and (ast1 != '' and ast2 != ''):
        # print ast1, ast2
        try:
            v3 = difference_ratio(decimal.Decimal(ast1), decimal.Decimal(ast2))
        except:
            v3 = 0.0
    v3 /= 2

    v4 = 0.0
    if md1 == md2 and md1 is not None and float(md1) > 0.0:
        # A MD-Index >= 10.0 is somehow rare
        md1 = float(md1)
        if md1 > 10.0:
            return 1.0
        v4 = min((v1 + v2 + v3 + v4 + 3.0) / 4, 1.0)

    r = max(v1, v2, v3, v4)
    return r


def make_score(row, cur):
    """
    calculate the matched ratio
    @param row : functions information to be matched
        cur : sql operator
    @return matched ratio
    """
    r = check_ratio(str(row[8]), str(row[9]),
                    str(row[6]), str(row[7]),
                    str(row[10]), str(row[11]),
                    str(row[12]), str(row[13]))
    consts1 = json.loads(str(row[14]))
    consts2 = json.loads(str(row[15]))
    nums1 = json.loads(str(row[16]))
    nums2 = json.loads(str(row[17]))
    lnums1 = json.loads(str(row[18]))
    lnums2 = json.loads(str(row[19]))
    v5 = compare_consts(consts1, consts2)
    v6 = compare_numbers(nums1, nums2)
    v7 = compare_numbers(lnums1, lnums2)
    v8 = compare_callee(str(row[4]), str(row[0]), cur)

    print r, v5, v6, v7, v8

    return r + v5/100 + v6/100 + v7/100 + v8/10


#---------------------------------------------------------------------------
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
# EDGE_IN_UNCONDITIONAL = 13
# EDGE_OUT_UNCONDITIONAL = 17

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


def strongly_connected_components(graph):
    """ Find the strongly connected components in a graph using
        Tarjan's algorithm.

        graph should be a dictionary mapping node names to
        lists of successor nodes.
        """

    result = []
    stack = []
    low = {}

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


def topological_sort(graph):
    count = {}
    for node in graph:
        count[node] = 0
    for node in graph:
        for successor in graph[node]:
            count[successor] += 1

    ready = [node for node in graph if count[node] == 0]

    result = []
    while ready:
        node = ready.pop(-1)
        result.append(node)

        for successor in graph[node]:
            count[successor] -= 1
            if count[successor] == 0:
                ready.append(successor)

    return result


def robust_topological_sort(graph):
    """ First identify strongly connected components,
        then perform a topological sort on these components. """

    components = strongly_connected_components(graph)

    node_component = {}
    for component in components:
        for node in component:
            node_component[node] = component

    component_graph = {}
    for component in components:
        component_graph[component] = []
    for node in graph:
        node_c = node_component[node]
        for successor in graph[node]:
            successor_c = node_component[successor]
            if node_c != successor_c:
                component_graph[node_c].append(successor_c)

    return topological_sort(component_graph)


def get_node_value(succs, preds):
    """ Return a set of prime numbers corresponding to the characteristics of the node. """
    ret = 1
    if succs == 0:
        ret *= NODE_ENTRY

    if preds == 0:
        ret *= NODE_EXIT

    ret *= NODE_NORMAL
    return ret


def get_edges_value(bb, succs, preds):
    ret = 1
    for _ in succs:
        ret *= EDGE_OUT_CONDITIONAL

    for _ in preds:
        ret *= EDGE_IN_CONDITIONAL

    return ret


def cfg_hash(func):
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

        hash *= get_node_value(len(succs), len(preds))
        hash *= get_edges_value(block, succs, preds)

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
        strongly_connected = strongly_connected_components(bb_relations)
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
        bb_topological_sorted = robust_topological_sort(bb_topological)
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


#---------------------------------------------------------------------------
CMP_REPS = ["loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
  "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
  "stru_", "dbl_", "locret_"]
CMP_REMS = ["dword ptr ", "byte ptr ", "word ptr ", "qword ptr ", "short ptr"]
CMP_SYMS = ["j_", "j__", " _", "__"]


def do_decompile(f):
    if IDA_SDK_VERSION >= 730:
        return decompile(f, flags=idaapi.DECOMP_NO_WAIT)
    return decompile(f)


def get_code_hash(f, pseudo):
    pseudo_hash1 = None
    pseudo_hash2 = None
    pseudo_hash3 = None
    pseudocode_primes = None
    if pseudo != '':
        cfunc = do_decompile(f)
        visitor = CAstVisitor(cfunc)
        visitor.apply_to(cfunc.body, None)
        pseudocode_primes = str(visitor.primes_hash)
        kfh = CKoretFuzzyHashing()
        kfh.bsize = 32
        pseudo_hash1, pseudo_hash2, pseudo_hash3 = kfh.hash_bytes(pseudo).split(";")
        if pseudo_hash1 == "":
            pseudo_hash1 = None
        if pseudo_hash2 == "":
            pseudo_hash2 = None
        if pseudo_hash3 == "":
            pseudo_hash3 = None
    return (pseudocode_primes, pseudo_hash1, pseudo_hash2, pseudo_hash3)


def get_mnemonics_spp(f):
    info = get_inf_structure()
    cpu_struct = info.procName
    if cpu_struct == 'ARM' or cpu_struct == 'ARMB':
        thumb_end_list = ['EQ', 'NE', 'CS', 'HS', 'CC', 'LO', 'MI', 'PL', 'VS',
                          'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL']
        bits_end_list = ['W', 'L', 'B', 'H', 'S']
    else:
        thumb_end_list = []
        bits_end_list = []
    func = get_func(f)
    cpu_ins_list = GetInstructionList()
    cpu_ins_list += thumb_end_list
    primes = primesblow(2048 * 2048)
    cpu_ins_list.sort()
    mnemonics_spp = 1
    for line in list(Heads(func.startEA, func.endEA)):
        mnem = GetMnem(line).split('.')[0]
        if mnem[-2:] in thumb_end_list and mnem[:-2] in cpu_ins_list:
            mnemonics_spp *= primes[cpu_ins_list.index(mnem[-2:])]
            mnem = mnem[:-2]
        if mnem[-1:] in bits_end_list and mnem[:-1] in cpu_ins_list and len(mnem) > 1:
            mnem = mnem[:-1]
        if mnem in cpu_ins_list:
            mnemonics_spp *= primes[cpu_ins_list.index(mnem)]
    return mnemonics_spp


class CodeClean:
    def __init__(self):
        self.re_cache = {}

    def re_sub(self, text, repl, string):
        if text not in self.re_cache:
            self.re_cache[text] = re.compile(text, flags=re.IGNORECASE)

        re_obj = self.re_cache[text]
        return re_obj.sub(repl, string)

    def get_cmp_asm(self, asm):
        if asm is None:
            return asm

        # Ignore the comments in the assembly dump
        tmp = asm.split(";")[0]
        tmp = tmp.split(" # ")[0]
        # Now, replace sub_, byte_, word_, dword_, loc_, etc...
        for rep in CMP_REPS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", "XXXX", tmp)

        # Remove dword ptr, byte ptr, etc...
        for rep in CMP_REMS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", "", tmp)

        for rep in CMP_SYMS:
            tmp = self.re_sub(rep + "[a-zA-Z][a-z0-9A-Z_]+", "XXXX", tmp)

        if "=(" in tmp:
            tmp = tmp.split("=(")[0] + "XXXX"

        reps = ["\+[a-f0-9A-F]+h\+"]
        for rep in reps:
            tmp = self.re_sub(rep, "+XXXX+", tmp)
        tmp = self.re_sub("\.\.[a-f0-9A-F]{8}", "XXX", tmp)

        # Strip any possible remaining white-space character at the end of
        # the cleaned-up instruction
        tmp = self.re_sub("[ \t\n]+$", "", tmp)

        # Replace aName_XXX with aXXX, useful to ignore small changes in
        # offsets created to strings
        tmp = self.re_sub("a[A-Z]+[a-z0-9]+_[0-9]+", "aXXX", tmp)
        return tmp

    def get_cmp_asm_lines(self, asm):
        sio = StringIO(asm)
        lines = []
        for line in sio.readlines():
            line = line.strip("\n")
            lines.append(self.get_cmp_asm(line))
        return "\n".join(lines)

    def get_cmp_pseudo_lines(self, pseudo):
        if pseudo is None:
            return pseudo

        # Remove all the comments
        tmp = self.re_sub(" // .*", "", pseudo)

        # Now, replace sub_, byte_, word_, dword_, loc_, etc...
        for rep in CMP_REPS:
            tmp = self.re_sub(rep + "[a-f0-9A-F]+", rep + "XXXX", tmp)
        tmp = self.re_sub("v[0-9]+", "vXXX", tmp)
        tmp = self.re_sub("a[0-9]+", "aXXX", tmp)
        tmp = self.re_sub("arg_[0-9]+", "aXXX", tmp)
        return tmp


class CAstVisitor(ctree_visitor_t):
    def __init__(self, cfunc):
        self.primes = primesblow(4096)
        ctree_visitor_t.__init__(self, CV_FAST)
        self.cfunc = cfunc
        self.primes_hash = 1
        return

    def visit_expr(self, expr):
        try:
            self.primes_hash *= self.primes[expr.op]
        except:
            traceback.print_exc()
        return 0

    def visit_insn(self, ins):
        try:
            self.primes_hash *= self.primes[ins.op]
        except:
            traceback.print_exc()
        return 0


class CKoretFuzzyHashing:
    """ Generate partial hashes of files or bytes """
    bsize = 512
    output_size = 32
    ignore_range = 2
    big_file_size = 1024 * 1024 * 10
    algorithm = None
    reduce_errors = True
    remove_spaces = False

    def get_bytes(self, f, initial, final):
        f.seek(initial)
        return f.read(final)

    def edit_distance(self, sign1, sign2):
        if sign1 == sign2:
            return 0

        m = max(len(sign1), len(sign2))
        distance = 0

        for c in xrange(0, m):
            if sign1[c:c + 1] != sign2[c:c + 1]:
                distance += 1

        return distance

    def simplified(self, bytes, aggresive=False):
        output_size = self.output_size
        bsize = self.bsize
        total_size = len(bytes)
        size = (total_size / bsize) / output_size
        buf = []
        reduce_errors = self.reduce_errors
        # Adjust the output to the desired output size
        for c in xrange(0, output_size):
            tmp = bytes[c * size:(c * size + 1) + bsize]
            ret = sum(imap(ord, tmp)) % 255
            if reduce_errors:
                if ret != 255 and ret != 0:
                    buf.append(chr(ret))
            else:
                buf.append(chr(ret))

        buf = "".join(buf)
        return base64.b64encode(buf).strip("=")[:output_size]

    def modsum(self, buf):
        return sum(imap(ord, buf)) % 255

    def _hash(self, bytes, aggresive=False):
        idx = 0
        ret = []

        output_size = self.output_size
        ignore_range = self.ignore_range
        bsize = self.bsize
        total_size = len(bytes)
        rappend = ret.append
        reduce_errors = self.reduce_errors
        # Calculate the sum of every block
        while 1:
            chunk_size = idx * bsize
            # print "pre"
            buf = bytes[chunk_size:chunk_size + bsize]
            # print "post"
            char = self.modsum(buf)

            if reduce_errors:
                if char != 255 and char != 0:
                    rappend(chr(char))
            else:
                rappend(chr(char))

            idx += 1

            if chunk_size + bsize > total_size:
                break

        ret = "".join(ret)
        size = len(ret) / output_size
        buf = []

        # Adjust the output to the desired output size
        for c in xrange(0, output_size):
            if aggresive:
                buf.append(ret[c:c + size + 1][ignore_range:ignore_range + 1])
            else:
                buf.append(ret[c:c + size + 1][1:2])

            i = 0
            for x in ret[c:c + size + 1]:
                i += 1
                if i != ignore_range:
                    continue
                i = 0
                buf += x
                break

        ret = "".join(buf)

        return base64.b64encode(ret).strip("=")[:output_size]

    def _fast_hash(self, bytes, aggresive=False):
        i = -1
        ret = set()

        output_size = self.output_size
        bsize = self.bsize
        radd = ret.add

        while i < output_size:
            i += 1
            buf = bytes[i * bsize:(i + 1) * bsize]
            char = sum(imap(ord, buf)) % 255
            if self.reduce_errors:
                if char != 255 and char != 0:
                    radd(chr(char))
            else:
                radd(chr(char))

        ret = "".join(ret)
        return base64.b64encode(ret).strip("=")[:output_size]

    def xor(self, bytes):
        ret = 0
        for byte in bytes:
            ret ^= byte
        return ret

    def _experimental_hash(self, bytes, aggresive=False):
        idx = 0
        ret = []
        bsize = self.bsize
        output_size = self.output_size
        size = len(bytes)
        chunk_size = idx * self.bsize
        byte = None

        while size > chunk_size + (bsize / output_size):
            chunk_size = idx * self.bsize
            if byte is None:
                val = bsize
            elif ord(byte) > 0:
                val = ord(byte)
            else:
                val = output_size

            buf = bytes[chunk_size:chunk_size + val]
            byte = self.xor(imap(ord, buf)) % 255
            byte = chr(byte)

            if byte != '\xff' and byte != '\x00':
                ret.append(byte)

            idx += 1

        ret = "".join(ret)
        buf = ""
        size = len(ret) / output_size
        for n in xrange(0, output_size):
            buf += ret[n * size:(n * size) + 1]

        return base64.b64encode(buf).strip("=")[:output_size]

    def mix_blocks(self, bytes):
        idx = 0
        buf = bytes
        ret = ""
        size1 = 0
        size2 = 0

        while 1:
            size1 = idx * self.bsize
            size2 = (idx + 1) * self.bsize

            tmp = buf[size1:size2]
            tm2 = tmp
            ret += tmp
            ret += tm2

            idx += 1

            if len(tmp) < self.bsize:
                break

        return ret

    def cleanSpaces(self, bytes):
        bytes = bytes.replace(" ", "").replace("\r", "").replace("\n", "")
        bytes = bytes.replace("\t", "")
        return bytes

    def hash_bytes(self, bytes, aggresive=False):
        if self.remove_spaces:
            bytes = self.cleanSpaces(bytes)

        mix = self.mix_blocks(bytes)
        if self.algorithm is None:
            func = self._hash
        else:
            func = self.algorithm

        hash1 = func(mix, aggresive)
        hash2 = func(bytes, aggresive)
        hash3 = func(bytes[::-1], aggresive)

        return hash1 + ";" + hash2 + ";" + hash3

