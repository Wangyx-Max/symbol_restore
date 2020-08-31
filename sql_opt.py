#!/usr/bin/python
import sqlite3
import json


sql_dict = {}
sql_dict['strings_match'] = """select * from diff.constants where func_id in (
                select func_id from (
                    select * from diff.constants where LENGTH(constant) > %s group by constant having count(*) == 1
                ) 
                group by func_id having count(*) == 1
            )
            and constant in (
                select constant from diff.constants where LENGTH(constant) > %s group by constant having count(*) == 1
            )
                    """
sql_dict['Same Name Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                df.address src_address, 'Same Name Match' description
        from functions f,
             diff.functions df
        where df.name_hash = f.name_hash
        union
        select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                df.address src_address, 'Same Name Match' description
        from functions f,
             diff.functions df
        where df.mangled_hash = f.mangled_hash
        """
sql_dict['Rare Bytes Hash Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Bytes Hash Match' description
                    from (select * from functions group by bytes_hash having count(bytes_hash) = 1) f,
                    diff.functions df
                    where f.bytes_hash = df.bytes_hash
                    and f.address not in (select bin_address from results)
                    and df.address not in (select src_address from results)
                    group by ea having count(ea) = 1
            """
sql_dict['Rare Mnemonics Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Rare Mnemonics Match' description
                    from (select * from functions group by mnemonics, numbers, numbers2 having count(*) = 1) f,
                    diff.functions df
                    where f.mnemonics = df.mnemonics
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
                    and f.instructions > 2
                    and f.address not in (select bin_address from results)
                    and df.address not in (select src_address from results)
                    group by ea having count(ea) = 1
            """

sql_dict['Rare Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Rare Constants Match' description
                    from diff.functions df,
                    (select * from functions 
                    where constants_count > 1 or numbers_count > 10 or numbers2_count > 2 
                    group by constants, numbers, numbers2 having count(*) = 1) f
                    where f.constants = df.constants
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
                    and f.address not in (select bin_address from results)
                    and df.address not in (select src_address from results) 
                    group by ea having count(ea) = 1
            """
sql_dict['Mnemonics Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
                df.address src_address, 'Mnemonics and Constants Match' description
                    from diff.functions df,
                        (select * from functions 
                        where constants_count > 0 or numbers_count > 5 or numbers2_count > 0 
                        group by mnemonics, constants, numbers, numbers2 having count(*) = 1) f
                    where f.mnemonics = df.mnemonics
                    and f.constants = df.constants
                    and f.numbers = df.numbers
                    and f.address not in (select bin_address from results)
                    and df.address not in (select src_address from results)
                    group by ea having count(ea) = 1
            """

sql_dict['Rare Md_Index Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'Rare MD Index Match' description
                from diff.functions df,
                     (select * from functions where md_index != 0 group by md_index having count(*) == 1) f
                where f.md_index = df.md_index
                and f.size = df.size 
                and f.instructions = df.instructions
                and f.address not in (select bin_address from results)
                and df.address not in (select src_address from results)
                group by ea having count(ea) = 1 
        """
sql_dict['Rare KOKA Hash Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'Rare KOKA Hash Match' description
           from diff.functions df,
                (select * from functions where kgh_hash != 0 group by kgh_hash having count(*) == 1) f
                where f.kgh_hash = df.kgh_hash
                and f.size = df.size 
                and f.instructions = df.instructions
                and f.numbers = df.numbers
                and f.address not in (select bin_address from results)
                and df.address not in (select src_address from results)
                group by ea having count(ea) = 1 
"""
sql_dict['Md_Index Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'MD_Index and Constants Match' description
                from diff.functions df,
                     (select * from functions 
                     where md_index != 0 and (constants_count > 0 or numbers_count > 5 or numbers2_count > 0) 
                     group by md_index, constants, numbers, numbers2 having count(*) == 1) f
                where f.md_index = df.md_index
                and f.constants = df.constants
                and f.numbers = df.numbers
                and f.instructions = df.instructions
                and f.address not in (select bin_address from results)
                and df.address not in (select src_address from results)
                group by ea having count(ea) = 1
        """
sql_dict['KOKA Hash Constants Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
                        df.address src_address, 'KOKA Hash and Constants Match' description
                from diff.functions df,
                     (select * from functions 
                     where kgh_hash != 0 and (constants_count > 0 or numbers_count > 5 or numbers2_count > 0) 
                     group by kgh_hash, constants, numbers, number2 having count(*) == 1) f
                where f.kgh_hash = df.kgh_hash
                and f.constants = df.constants
                and f.numbers = df.numbers
                and f.address not in (select bin_address from results)
                and df.address not in (select src_address from results)
                group by ea having count(ea) = 1
        """

sql_dict['Bytes Hash Neighbor Match'] = """select distinct f.address bin_addr, f.name bin_name, df.id src_id, df.name src_name, df.address src_addr,
                    'Bytes Hash Neighbor Match' description, f.id bin_id
                    from functions f,
                        diff.functions df
                    where f.bytes_hash = df.bytes_hash
                    and f.instructions > 1
                    and f.address not in (select bin_address from results)
        """
sql_dict['Mnemonics Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Mnemonics Neighbor Match' description, f.id bin_id
                    from functions f,
                        diff.functions df
                    where f.mnemonics = df.mnemonics
                    and f.instructions > 5
                    and f.address not in (select bin_address from results)
        """
sql_dict['Constants Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Constants Neighbor Match' description, f.id bin_id
                    from functions f,
                        (select * from diff.functions 
                        where constants_count > 0 or numbers_count > 5 or numbers2_count > 0) df
                    where f.constants = df.constants
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
                    and f.address not in (select bin_address from results)
        """
sql_dict['MD Index Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'MD Index Neighbor Match' description, f.id bin_id
                    from (select * from functions where md_index != 0) f,
                        (select * from diff.functions where md_index != 0) df
                    where f.md_index = df.md_index
                    and f.size = df.size
                    and f.instructions = df.instructions
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
                    and f.address not in (select bin_address from results)
        """
sql_dict['KOKA Hash Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'KOKA Hash Neighbor Match' description, f.id bin_id
                    from (select * from functions where kgh_hash != 0) f,
                        (select * from diff.functions where kgh_hash != 0) df
                    where f.kgh_hash = df.kgh_hash
                    and f.kgh_hash != 0
                    and f.size = df.size
                    and f.instructions = df.instructions
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
                    and f.address not in (select bin_address from results)
        """
sql_dict['Assembly Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Assembly Neighbor Match' description, f.id bin_id
                    from (select * from functions where assembly != 0) f,
                        (select * from diff.functions where assembly != 0) df
                    where f.assembly = df.assembly
                    and f.address not in (select bin_address from results)
"""
sql_dict['Clean Assembly Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Clean Assembly Neighbor Match' description, f.id bin_id
                    from (select * from functions where clean_assembly != 0) f,
                        (select * from diff.functions where clean_assembly != 0) df
                    where f.clean_assembly = df.clean_assembly
                    and f.address not in (select bin_address from results)
"""
sql_dict['Pseudocode Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Assembly Neighbor Match' description, f.id bin_id
                    from (select * from functions where pseudocode != 0) f,
                        (select * from diff.functions where pseudocode != 0) df
                    where f.pseudocode = df.pseudocode
                    and f.pseudocode_lines > 1
                    and f.address not in (select bin_address from results)
"""
sql_dict['Clean Pseudocode Neighbor Match'] = """
                    select distinct f.address bin_addr, f.name bin_name, df.id src_func_id, df.name src_name, df.address src_addr,
                    'Clean Assembly Neighbor Match' description, f.id bin_id
                    from (select * from functions where clean_pseudo != 0) f,
                        (select * from diff.functions where clean_pseudo != 0) df
                    where f.clean_pseudo = df.clean_pseudo
                    and f.pseudocode_lines > 1
                    and f.address not in (select bin_address from results)
"""

sql_dict['Rare Pseudocode Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Pseudocode Match' description
                    from (select * from functions group by pseudocode having count(*) = 1) f,
                    diff.functions df
                    where f.pseudocode = df.pseudocode
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""
sql_dict['Rare Assembly Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Assembly Match' description
                    from (select * from functions group by assembly having count(*) = 1) f,
                    diff.functions df
                    where f.assembly = df.assembly
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""
sql_dict['Rare Clean Pseudocode Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Clean Pseudocode Match' description
                    from (select * from diff.functions group by clean_pseudo having count(*) = 1) f,
                    functions df
                    where f.clean_pseudo = df.clean_pseudo
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""
sql_dict['Rare Clean Assembly Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Clean Assembly Match' description
                    from (select * from functions group by clean_assembly having count(*) = 1) f,
                    diff.functions df
                    where f.clean_assembly = df.clean_assembly
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""

sql_dict['Rare Mnemonics Spp Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Mnemonics Spp Match' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions group by mnemonics_spp having count(*) = 1) f,
                    diff.functions df
                    where f.mnemonics_spp = df.mnemonics_spp
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""
sql_dict['Rare Pseudocode Fuzzy Hash Match(Mixed)'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Pseudocode Fuzzy Hash Match(Mixed)' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,      
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions group by pseudocode_hash1 having count(*) = 1) f,
                    diff.functions df
                    where f.pseudocode_hash1 = df.pseudocode_hash1
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""
sql_dict['Rare Pseudocode Fuzzy Hash Match(AST)'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Pseudocode Fuzzy Hash Match(AST)' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions group by pseudocode_primes having count(*) = 1) f,
                    diff.functions df
                    where f.pseudocode_primes = df.pseudocode_primes
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""
sql_dict['Rare Pseudocode Fuzzy Hash Match(Normal)'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Pseudocode Fuzzy Hash Match(Normal)' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions group by pseudocode_hash2 having count(*) = 1) f,
                    diff.functions df
                    where f.pseudocode_hash2 = df.pseudocode_hash2
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""
sql_dict['Rare Pseudocode Fuzzy Hash Match(Reverse)'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Rare Pseudocode Fuzzy Hash Match(Reverse)' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions group by pseudocode_hash2 having count(*) = 1) f,
                    diff.functions df
                    where f.pseudocode_hash3 = df.pseudocode_hash3
                    and f.address not in (select bin_address from results)
                    group by ea having count(ea) = 1
"""

sql_dict['Supplement Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Supplement Match' description
                    from (select * from functions 
                            where address not in (select bin_address from results
                                            union select bin_address from results_multi)
                            group by address having count(*) = 1) f,
                        (select * from diff.functions 
                            where address not in (select bin_address from results 
                                            union select bin_address from results_multi)) df
                    where f.bytes_hash = df.bytes_hash
                    group by f.address having count(*) = 1
"""
sql_dict['Linker Optimization Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Linker Optimization Match' description
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi)
                         group by bytes_hash having count(bytes_hash) = 1) f,
                    (select * from diff.functions
                    where address not in (select src_address from results
                                    union select src_address from results_multi)) df
                    where f.bytes_hash = df.bytes_hash
"""
sql_dict['Same Bytes Hash Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Same Bytes Hash Match' description
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi)) f,
                    (select * from diff.functions
                    where address not in (select src_address from results
                                    union select src_address from results_multi)) df
                    where f.bytes_hash = df.bytes_hash
"""

sql_dict['Mnemonics Score Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Same Mnemonics Match' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f,
                    (select * from diff.functions
                    where address not in (select src_address from results
                                    union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.mnemonics = df.mnemonics
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
"""
sql_dict['Constants Score Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'Constants Score Match' description, 
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f, 
                        (select * from diff.functions
                         where address not in (select src_address from results
                                        union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.constants = df.constants
                    and f.numbers = df.numbers
                    and f.numbers2 = df.numbers2
"""
sql_dict['MD Index Score Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'MD Index Score Match' description, 
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f, 
                        (select * from diff.functions
                         where address not in (select src_address from results
                                        union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.md_index = df.md_index
                    and f.md_index != 0
"""
sql_dict['KOKA Hash Score Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name, 
        df.address src_address, 'KOKA Hash Score Match' description, 
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f, 
                        (select * from diff.functions
                         where address not in (select src_address from results
                                        union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.kgh_hash = df.kgh_hash
                    and f.kgh_hash != 0
"""

sql_dict['Mnemonics Spp Match'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
        df.address src_address, 'Assembly Spp Match' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f,
                        (select * from diff.functions
                        where address not in (select src_address from results
                                        union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.mnemonics_spp = df.mnemonics_spp
"""
sql_dict['Pseudocode Fuzzy Hash Match(Mixed)'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
        df.address src_address, 'Pseudocode Fuzzy Hash Match(Mixed)' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f,
                        (select * from diff.functions
                        where address not in (select src_address from results
                                        union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.pseudocode_hash1 = df.pseudocode_hash1
"""
sql_dict['Pseudocode Fuzzy Hash Match(AST)'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
        df.address src_address, 'Pseudocode Fuzzy Hash Match(AST)' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f,
                        (select * from diff.functions
                         where address not in (select src_address from results
                                        union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.pseudocode_primes = df.pseudocode_primes
"""
sql_dict['Pseudocode Fuzzy Hash Match(Normal)'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
        df.address src_address, 'Pseudocode Fuzzy Hash Match(Normal)' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f,
                        (select * from diff.functions
                         where address not in (select src_address from results
                                        union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.pseudocode_hash2 = df.pseudocode_hash2
"""
sql_dict['Pseudocode Fuzzy Hash Match(Reverse)'] = """select distinct f.address ea, f.name bin_name, df.id src_func_id, df.name src_name,
        df.address src_address, 'Pseudocode Fuzzy Hash Match(Reverse)' description,
        f.clean_assembly asm1, df.clean_assembly asm2, f.clean_pseudo pseudo1, df.clean_pseudo pseudo2,
        f.pseudocode_primes ast1, df.pseudocode_primes ast2,
        f.md_index mdx1, df.md_index mdx2, f.constants consts1, df.constants consts2, f.numbers nums1, df.numbers nums2,
        f.numbers2 lnums1, df.numbers2 lnums2
                    from (select * from functions 
                        where address not in (select bin_address from results
                                        union select bin_address from results_multi
                                        union select bin_address from results_fuzzy)) f,
                        (select * from diff.functions
                         where address not in (select src_address from results
                                        union select src_address from results_multi
                                        union select src_address from results_fuzzy)) df
                    where f.pseudocode_hash3 = df.pseudocode_hash3
"""


def create_sql_props(l):
    props = []
    for prop in l:
        if type(prop) is long and (prop > 0xFFFFFFFF or prop < -0xFFFFFFFF):
            prop = str(prop)
        if type(prop) is list or type(prop) is set:
            props.append(json.dumps(list(prop), ensure_ascii=False))
        else:
            props.append(prop)
    return props


class SqlOperate:
    def __init__(self, name):
        self.db_name = name
        self.conn = None
        self.cur = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()
        self.conn.text_factory = str
        self.conn.row_factory = sqlite3.Row
        return self.conn, self.cur

    def attach(self, name):
        self.connect()
        try:
            self.cur.execute('attach "%s" as diff' % name)
            self.conn.commit()
        except:
            print "sqlite attach error"
        return self.conn, self.cur

    def create_results(self):
        self.connect()
        sql = """create table if not exists results (
                    bin_address integer unique,
                    bin_name varchar(255), 
                    src_address integer unique,
                    src_name varchar(255), 
                    description varchar(255),
                    primary key(src_name))"""
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create results error")
        finally:
            self.cur.close()

    def create_results_multi(self):
        self.connect()
        sql = """create table if not exists results_multi (
                    bin_address integer,
                    bin_name varchar(255), 
                    src_address integer,
                    src_name varchar(255), 
                    description varchar(255),
                    primary key(bin_address, src_address))"""
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create results_multi error")
        finally:
            self.cur.close()

    def create_results_fuzzy(self):
        self.connect()
        sql = """create table if not exists results_fuzzy (
                    id integer primary key,
                    bin_address integer,
                    bin_name varchar(255), 
                    src_address integer,
                    src_name varchar(255), 
                    ratio real,
                    description varchar(255))"""
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create results_fuzzy error")

    def create_functions(self):
        self.connect()
        sql = """ create table if not exists functions (
            id integer primary key,
            address integer unique,
            name varchar(255),
            mangled_function text,
            name_hash text,
            mangled_hash text,
            function_flags integer,
            size integer,
            instructions integer,
            bytes_hash text,
            mnemonics text,
            numbers text,
            numbers_count integer,
            numbers2 text,
            numbers2_count integer,
            
            callers text,
            callers_count integer,
            
            constants text,
            constants_count integer,
            
            md_index text,
            kgh_hash text,
            nodes integer,
            
            assembly text,
            clean_assembly text,
            pseudocode text,
            clean_pseudo text,
            pseudocode_lines integer,
            mnemonics_spp text,
            pseudocode_primes text,
            pseudocode_hash1 text,
            pseudocode_hash2 text,
            pseudocode_hash3 text
            ) """
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create functions error!")
        finally:
            self.cur.close()

    def create_constants(self):
        self.connect()
        sql = """create table if not exists constants (
                func_id integer not null references functions(id) on delete cascade,
                constant text not null,
                primary key(func_id, constant))
        """
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create constants error!")
        finally:
            self.cur.close()

    def create_callers(self):
        self.connect()
        sql = """create table if not exists callers(
                caller_id integer not null references functions(id) on delete cascade,
                caller_address text not null,
                call_address text not null,
                callee_address text not null,
                primary key(caller_address, callee_address))
        """
        try:
            self.cur.execute(sql)
            self.conn.commit()
        except:
            print("create callers error!")
        finally:
            self.cur.close()

    def read_functions(self, bin_address, src_address=0, src_name=None):
        self.connect()
        sql = """select * from functions where address = %s
        """
        self.cur.execute(sql % bin_address)
        bin = self.cur.fetchone()
        src = None
        if src_name is not None:
            self.attach(src_name)
            sql = """select * from diff.functions where address = %s
            """
            self.cur.execute(sql % src_address)
            src = self.cur.fetchone()
            self.cur.close()
        if self.cur is not None:
            self.cur.close()
        return bin, src

    def read_results(self):
        self.connect()
        sql = """select * from results"""
        try:
            self.cur.execute(sql)
            res = self.cur.fetchall()
        except:
            res = []
        finally:
            self.cur.close()
        return res

    def read_results_multi(self, t=''):
        self.connect()
        if t == '':
            sql = """select * from results_multi"""
        elif t == 'show':
            sql = """select * from results_multi group by bin_address"""
        try:
            self.cur.execute(sql)
            res = self.cur.fetchall()
        except:
            res = []
        finally:
            self.cur.close()
        return res

    def read_results_fuzzy(self, des=None):
        self.connect()
        try:
            if des is None:
                sql = """select * from results_fuzzy"""
                self.cur.execute(sql)
                res = self.cur.fetchall()
            else:
                sql = """select * from results_fuzzy where description like '% Score Match'"""
                self.cur.execute(sql)
                res = self.cur.fetchall()
        except:
            res = []
        finally:
            self.cur.close()
        return res

    def read_results_instr(self, src_name):
        self.attach(src_name)
        sql = """select * from results
                    """
        self.cur.execute(sql)
        sql_bin = """select instructions, numbers, numbers2 from functions where address = %s 
                """
        sql_src = """select instructions, numbers, numbers2 from diff.functions where address = %s 
                """

        rows = self.cur.fetchall()
        res = []
        sum = 0
        s = 0
        for row in rows:
            sum += 1
            self.cur.execute(sql_bin % (row[0]))
            bin = self.cur.fetchone()
            self.cur.execute(sql_src % (row[2]))
            src = self.cur.fetchone()
            if bin and src and str(bin[0]) != str(src[0]):
                res.append((row, bin[0], src[0], bin[1], src[1], bin[2], src[2]))
                s += 1
        return res

    def read_constants(self, name=None):
        if name is None:
            self.connect()
            sql_func_id = """select distinct func_id from constants 
                        group by func_id having count(func_id) > 1
                """
            sql_cons = """select constant from constants where func_id = %s"""
        else:
            self.attach(name)
            sql_func_id = """select distinct func_id from diff.constants 
                        group by func_id having count(func_id) > 1
                """
            sql_cons = """select constant from diff.constants where func_id = %s"""
        self.cur.execute(sql_func_id)
        rows = self.cur.fetchall()
        dict = {}
        for row in rows:
            self.cur.execute(sql_cons % str(row[0]))
            constants = self.cur.fetchall()
            new_constants = []
            for constant in constants:
                new_constants.append(str(constant))
            new_constants = json.dumps(new_constants)
            try:
                dict[new_constants].append(str(row[0]))
            except:
                dict[new_constants] = [str(row[0])]
        if self.cur is not None:
            self.cur.close()
        return dict

    def read_results_des(self, dess, output=False):
        self.connect()
        for des in dess:
            sql = """select * from results where description == '%s'
            """
            self.cur.execute(sql % des)
            rows = self.cur.fetchall()
            try:
                res += rows
            except:
                res = rows
            if output is True:
                sum = 0
                for row in rows:
                    print str(row[0]) + '->' + str(row[2])
                    sum += 1
                print sum
        self.cur.close()
        # print res
        return res

    def read_results_test(self, src_name, attr, des=None):
        self.attach(src_name)
        if des is None:
            sql = """select * from results
            """
            self.cur.execute(sql)
        else:
            sql = """select * from results where description == %s
            """
            self.cur.execute(sql % des)
        sql_bin = """select %s from functions where address = %s 
        """
        sql_src = """select %s from diff.functions where address = %s 
        """

        rows = self.cur.fetchall()
        res = []
        sum = 0
        s = 0
        for row in rows:
            sum += 1
            self.cur.execute(sql_bin % (attr, row[0]))
            bin = self.cur.fetchone()
            self.cur.execute(sql_src % (attr, row[2]))
            src = self.cur.fetchone()
            if bin and src and str(bin[0]) != str(src[0]):
                if des is None:
                    print row[4]
                print str(row[0]) + '->' + str(row[2])
                res.append(row)
                s += 1
        print sum, s
        return res

    def read_results_fuzzy_test(self, src_name, attr, des=None):
        self.attach(src_name)
        if des is None:
            sql = """select * from results_fuzzy
            """
            self.cur.execute(sql)
        else:
            sql = """select * from results_fuzzy where description == %s
            """
            self.cur.execute(sql % des)
        sql_bin = """select %s from functions where address = %s 
        """
        sql_src = """select %s from diff.functions where address = %s 
        """

        rows = self.cur.fetchall()
        res = []
        sum = 0
        s = 0
        for row in rows:
            sum += 1
            self.cur.execute(sql_bin % (attr, row[1]))
            bin = self.cur.fetchone()
            self.cur.execute(sql_src % (attr, row[3]))
            src = self.cur.fetchone()
            if bin and src and str(bin[0]) != str(src[0]):
                if des is None:
                    print row[6]
                print str(row[2]) + '->' + str(row[4])
                res.append(row)
                s += 1
        print sum, s
        return res

    def test_sql_dict(self, name, key, output=False):
        self.attach(name)
        sql = sql_dict[key]
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        if output is True:
            for row in rows:
                print hex(int(row[0])) + '->' + hex(int(row[4]))
            print len(rows)
        return rows
