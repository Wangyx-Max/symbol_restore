### 使用方法
源代码编译后，在`pathto\app\build\intermediates\cmake\release\obj\armeabi-v7a\`文件夹下获得有符号信息的.so文件。
加载到ida，直接通过`file->script`执行`src_analyse.py`的脚本。
生成一个`diff.sqlite`数据库。
然后在同一文件夹下打开需要还原符号的脚本，执行`bin_diff.py`脚本。

注意编译架构和配置要相同。

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

### 整体运行流程

#### 有符号程序特征提取

![image-20200805120043322](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20200805120043322.png)

#### 函数匹配

![image-20200805141621265](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20200805141621265.png)

### 函数特征说明

#### 基本函数特征

以Sample中libcpp_empty_test.so中的函数``cocos2d::Label::removeChiled(cocos2d::Node *,bool)``为例，该函数的字节码、汇编指令如下：

![image-20200805143714739](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20200805143714739.png)

![image-20200805143346036](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20200805143346036.png)

下面介绍程序获取了哪些基本函数特征，为了方便理解，贴出上例程序通过IDA Python获得的基本特征结果：

**address**  函数的起始地址 

> ‘2085060’

**name** 函数名称

> 'cocos2d::labal::removeChiled(cocos2d::node *, bool)'

**mangled function** 函数名称 

> '_ZN7cocos2d5Label11removeChildEPNS_4NodeEb'

**function flags** 函数类型 

> '1048'

**size** 函数字节大小

> '42'

**functions hash** 指令哈希值 

> ‘b92811245361d539122dbf49a627e1fa’
>
> =md5(0xB0B502AF0D460446D6F7DEEA04F2DC41096849B1C868A842FAD104F2D4400831BDE8B04033F262BDB0BD)

**instructions** 指令数量

> '16'

**mnemonics** 指令序列 

> '["PUSH", "ADD", "MOV", "MOV", "BLX", "ADDW", "LDR", "CBZ", "LDR", "CMP", "BNE", "ADDW", "ADDS", "POP.W", "B.W", "POP"]'

**numbers** 第三个操作数为立即数时，将该立即数加入numbers集合

> ‘[8, 1244, 1236]’

**numbers count** numbers集合中立即数的数量

> ‘3’

#### 常量特征

以Sample中libcpp_empty_test.so中的函数``cocos2d::RenderCommand::printID(cocos2d::RenderCommand *this)``为例，该函数的汇编指令、伪代码如下：

![image-20200805144941396](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20200805144941396.png)

![image-20200805144956447](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20200805144956447.png)

下面介绍程序获取了哪些常量特征，为了方便理解，贴出上例程序通过IDA Python获得的基本特征结果：

**constants**  常量集合，常量”`$“是由于代码实现时，使用的``idautils.DataRefsFrom(x)``接口，会返回两个地址，具体原因不太清楚。

> '[" `$", "Command Depth: %f\n"]'

**constants count**  常量集合中常量数量

> '2'

上述所有特征均保存在表***Functions***中，在常量特征保存的时候，还会保存在另一个表中，下面将介绍该表的列。

***Constants***  

该表包括两列，一列用于存储调用了该常量的函数（**func_id**），另一列用于保存常量（**constant**）。注意该表只保存长度大于5的常量。

#### CFG哈希值

**md_index**

根据强连通分量算边的签名举例如下，该图最终计算出来的md_index的值为：2.899967761488782380784831865

![image-20200805150934882](C:\Users\Admin\AppData\Roaming\Typora\typora-user-images\image-20200805150934882.png)

**kgh_hash**

kgh哈希值的思想是将控制流程图的边、节点和指令分类，每种不同种类的边或节点都有不同的参数，所有参数累乘。再累乘上强连通分量参数、loop模块参数，最终得到kgh哈希值。

#### 函数调用关系

函数调用关系的获取，在实现时，其实是通过每个函数的被调用情况统计的。由于某些函数的调用可能跳转地址是.plt表的地址，也有可能某个地址未被识别成函数，所以通过被调情况来获取比较方便。

**callers**  调用该函数的函数起始地址序列

**callers_count** 调用该函数的函数数量

上述两特征只能表示该函数的被调用情况，且存储在***Functions***表中，下面介绍存储函数调用其他函数的表。

***Callers***

该表包括四列，每个函数调用的**id**号，调用函数的函数id（**caller_id**)，调用函数的初始函数地址（**caller_address**)，调用指令地址（**call_address**），被调用函数的初始地址（**callee_address**）

### 匹配规则设计

#### 字符串匹配

**String Match**

根据唯一引用的字符串筛选出如下函数：

* 函数中存在1条长度大于50的字符串
* 函数中存在2条长度大于30的字符串
* 函数中存在3条长度大于25的字符串
* 函数中存在4条长度大于15的字符串

字符串相等，函数匹配。

#### 基本特征匹配

**Same Name Match**

无符号函数与有符号函数名称相同，函数匹配。

**Bytes Hash Match**

获得每个函数的字节码哈希值，哈希值相同，函数匹配。

只对程序中字节哈希值唯一的函数进行匹配

**Rare Mnems Match**

获得每个函数的指令序列，指令数量大于5，指令序列相同、立即数序列也相同，函数匹配。

也只对程序中指令序列唯一的函数进行匹配

#### 常量特征匹配

**Long Constants Match**

函数中存在2条及以上长度大于5的字符串的函数，字符串相等，函数匹配。

**Rare Constants Match**

函数中的字符串序列在程序中唯一且相等，函数指令数量相等，函数匹配。

**Menmonics and Constants Match**

字符串数量大于0，指令数量大于5，字符串和指令序列相等，选取出的匹配结果为一对一时，函数匹配。

#### CFG哈希值匹配

**Rare MD Index Match**

md_index在程序中唯一且相等，函数节点大于5，函数匹配。

**Rare KOKA Hash**

KOKA哈希值在程序中唯一且相等，函数节点大于5，函数匹配。

**MD_Index and Constants Match**

函数CFG节点大于5，字符串数量大于0，md index值相等，字符串相等，选取出的匹配结果为一对一时，函数匹配。

**KOKA and Constants Match**

函数CFG节点大于5，字符串数量大于0，kgh hash值相等，字符串相等，选取出的匹配结果为一对一时，函数匹配。

#### 邻居匹配

**Neighbor Match**

选取如下几种函数：

* 无符号程序中字节哈希值不唯一，但与有符号程序中某函数字节哈希值相等
* 无符号程序中指令序列不唯一，指令数量大于5，但与有符号程序中某函数指令序列相等
* 函数中引用的字符串相同
* CFG哈希值（md_index或kgh_hash）相等，节点数量大于10

如果这些选取出来的函数的前一个函数被匹配，后一个函数也被匹配，且在有符号程序中，被匹配的两个函数中间只有一个函数，且该函数满足如上要求，两函数匹配。

#### 函数调用匹配




### 错误匹配
(Rare Mnemonics Match) -> bin_addr 882812 fixed

(Rare Mnemonics Match)src_addr 2616016 -> bin_addr 1636896 fixed

(Call Match)src_addr 4000930 -> bin_addr 1665876

(Rare KOKA Hash Match)src_addr 2256342 -> bin_addr 252758 fixed

