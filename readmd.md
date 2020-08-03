### 使用方法
源代码编译后，在`pathto\app\build\intermediates\cmake\release\obj\armeabi-v7a\`文件夹下获得有符号信息的.so文件。
加载到ida，直接通过`file->script`执行`src_analyse.py`的脚本。
生成一个`diff.sqlite`数据库。
然后在同一文件夹下打开需要还原符号的脚本，执行`bin_diff.py`脚本。

注意编译架构和配置最好完全相同。

### 运行结果

运行时间：8~9 分钟左右

| nums(sym_nums) | name                          |
| -------------- | ----------------------------- |
| 5356           | total                         |
| 181            | String Match                  |
| 261            | Same Name Match               |
| 1681           | Bytes Hash Match              |
| 618            | Rare Mnemonics Match          |
| 66             | Constants Match               |
| 72             | Rare Constants Match          |
| 12             | Menmonics and Constants Match |
| 636            | Rare MD Index Match           |
| 86             | Rare KOKA Hash Match          |
| 12             | MD_Index and Constants Match  |
| 161            | Neighbor Match                |
| 1570           | Call Match                    |



### 规则设计

**String Match**

根据唯一引用的字符串筛选出如下函数：

* 函数中存在1条长度大于50的字符串
* 函数中存在2条长度大于30的字符串
* 函数中存在3条长度大于25的字符串
* 函数中存在4条长度大于15的字符串

字符串相等，函数匹配。

**Same Name Match**

无符号函数与有符号函数名称相同，函数匹配。

**Bytes Hash Match**

获得每个函数的字节码哈希值，哈希值相同，函数匹配。

只对程序中字节哈希值唯一的函数进行匹配

**Rare Mnems Match**

获得每个函数的指令序列，指令数量大于5，指令序列相同，函数匹配。

也只对程序中指令序列唯一的函数进行匹配

**Constants Match**

函数中存在2条及以上长度大于10的字符串的函数，字符串相等，函数匹配。

**Rare Constants Match**

函数中的字符串序列在程序中唯一且相等，函数指令数量相等，函数匹配。

**Menmonics and Constants Match**

字符串数量大于0，指令数量大于5，字符串和指令序列相等，选取出的匹配结果为一对一时，函数匹配。

**Rare MD Index Match**

CFG特征值md_index在程序中唯一且相等，函数节点大于5，函数匹配。

**Rare KOKA Hash**

KOKA哈希值在程序中唯一且相等，函数节点大于5，函数匹配。

**MD_Index and Constants Match**

函数CFG节点大于5，字符串数量大于0，cfg特征值相等，字符串相等，选取出的匹配结果为一对一时，函数匹配。

**Neighbor Match**

选取如下几种函数：

* 无符号程序中字节哈希值不唯一，但与有符号程序中某函数字节哈希值相等
* 无符号程序中指令序列不唯一，指令数量大于5，但与有符号程序中某函数指令序列相等
* 函数中引用的字符串相同
* CFG哈希值（md_index或kgh_hash）相等，节点数量大于10

如果这些选取出来的函数的前一个函数被匹配，后一个函数也被匹配，且在有符号程序中，被匹配的两个函数中间只有一个函数，且该函数满足如上要求，两函数匹配。