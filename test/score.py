import decimal
import json
import random
import sys
from difflib import SequenceMatcher


def primesbelow(N):
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


smallprimeset = set(primesbelow(100000))
_smallprimeset = 100000
def isprime(n, precision=7):
    # http://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Algorithm_and_running_time
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
    smallprimes = primesbelow(10000)
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