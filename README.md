WinAFL

   Original AFL code written by Michal Zalewski <lcamtuf@google.com>

   Windows fork written and maintained by Ivan Fratric <ifratric@google.com>

   Copyright 2016 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
背景

AFL是覆盖引导模糊测试的流行模糊工具。该工具将快速目标执行与智能启发式相结合，以在目标二进制文件中查找新的执行路径。它已被成功地用于发现大量实际产品中的漏洞。有关原始项目的更多信息，请参阅原始文档：

http://lcamt​​uf.coredump.cx/afl/

不幸的是，由于非常特殊的nix设计（例如，仪器，叉式服务器等），原来的AFL在Windows上不起作用。这个项目是AFL的一个分支，它使用不同的仪器方法，即使在黑盒二进制模糊化的情况下也能在Windows上工作。

WinAFL方法

WinAFL不是在编译时使用代码，而是依靠使用DynamoRIO（http://dynamorio.org/）的动态工具来测量和提取目标覆盖率。已经发现，与原始执行速度相比，该方法引入了大约2倍的开销，这与在二进制仪器模式下的原始AFL相当。

AFL-fuzz.exe

为了提高进程启动时间，WinAFL在很大程度上依赖于持久性模糊模式，即执行多个输入采样而不重新启动目标进程。这是通过选择一个目标函数（用户想要模糊）并对其进行测试以使其运行在一个循环中来完成的。

WinAFL已成功用于识别Windows软件中的错误，例如

CVE-2016-7212 - 由Noser Engineering AG的Aral Yaman发现
CVE-2017-0073，CVE-2017-0190，CVE-2017-11816 - 由SensePost的Symeon Paraschoudis发现
（让我知道，如果你知道其他人，我会把他们列入清单）

构建WinAFL

从https://github.com/DynamoRIO/dynamorio/wiki/Downloads下载并构建DynamoRIO源代码或下载DynamoRIO Windows二进制包

打开Visual Studio命令提示符（或Visual Studio x64 Win64命令提示符，如果您想要一个64位版本）。请注意，如果您正在对64位目标进行模糊处理，则需要64位winafl.dll版本，反之亦然。

转到包含源的目录

输入以下命令。修改-DDynamoRIO_DIR标志以指向DynamoRIO cmake文件的位置（完整路径或相对于源目录）。

对于32位版本：

mkdir build32
cd build32
cmake .. -DDynamoRIO_DIR=..\path\to\DynamoRIO\cmake
cmake --build . --config Release
对于64位版本：

mkdir build64
cd build64
cmake -G"Visual Studio 10 Win64" .. -DDynamoRIO_DIR=..\path\to\DynamoRIO\cmake
cmake --build . --config Release
使用WinAFL

注意：如果您使用的是预构建的二进制文件，您需要从https://github.com/DynamoRIO/dynamorio/wiki/Downloads下载DynamoRIO版本6.2.0-2 。如果您从源代码构建WinAFL，则可以使用您用来构建WinAFL的任何版本的DynamoRIO。

Windows上的afl-fuzz命令行与Linux上的不同。代替：

%s [ afl options ] -- target_cmd_line
现在看起来像这样：

afl-fuzz [afl options] -- [instrumentation options] -- target_cmd_line
支持以下afl-fuzz选项：

  -i dir        - input directory with test cases
  -o dir        - output directory for fuzzer findings
  -D dir        - directory containing DynamoRIO binaries (drrun, drconfig)
  -t msec       - timeout for each run
  -f file       - location read by the fuzzed program
  -M \\ -S id   - distributed mode
  -x dir        - optional fuzzer dictionary
  -m limit      - memory limit for the target process
有关这些标志的更多信息，请参阅原始的AFL文档。

以下使用仪器选项：

  -covtype         - the type of coverage being recorded. Supported options are
                     bb (basic block, default) or edge.

  -coverage_module - module for which to record coverage. Multiple module flags
                     are supported.

  -target_module   - module which contains the target function to be fuzzed.
                     Either -target_method or -target_offset need to be
                     specified together with this option.

  -target_method   - name of the method to fuzz in persistent mode. For this to
                     work either the method needs to be exported or the symbols
                     for target_module need to be available. Otherwise use
                     -target_offset instead.

  -target_offset   - offset of the method to fuzz from the start of the module.

  -fuzz_iterations - Maximum number of iterations for the target function to run
                     before restarting the target process.

  -nargs           - Number of arguments the fuzzed method takes. This is used
                     to save/restore the arguments between runs.

  -debug           - Debug mode. Does not try to connect to the server. Outputs
                     a log file containing loaded modules, opened files and
                     coverage information.

  -logdir          - specifies in which directory the log file will be written
                     (only to be used with -debug).

  -call_convention - The default calling convention is cdecl on 32-bit x86
                     platforms and Microsoft x64 for Visual Studio 64-bit
                     applications. Possible values:
                         * fastcall: fastcall
                         * ms64: Microsoft x64 (Visual Studio)
                         * stdcall: cdecl or stdcall
                         * thiscall: thiscall

  -thread_coverage - If set, WinAFL will only collect coverage from a thread
                     that executed the target function
一般来说，在模糊一个新的目标时，你应该执行以下步骤：

确保您的目标没有仪器正确运行。

在WinDbg中打开目标二进制文件，找到你想要模糊的函数。注意功能从模块开始的偏移量。例如，如果您想模糊主要功能，并碰巧有符号，可以使用下面的windbg命令：

x test!main
确保目标在DynamoRIO下正确运行。为此，您可以使用不需要连接到afl-fuzz的WinAFL客户端的独立调试模式。确保使用与您的目标相对应的drrun.exe和winafl.dll版本（32位与64位）。
示例命令行：

path\to\DynamoRIO\bin64\drrun.exe -c winafl.dll -debug
-target_module test_gdiplus.exe -target_offset 0x1270 -fuzz_iterations 10
-nargs 2 -- test_gdiplus.exe input.bmp
您应该看到与您的目标函数运行10次相对应的输出，之后目标可执行文件将退出。应该在当前目录中创建一个.log文件。日志文件包含有用的信息，如目标加载的文件和模块以及AFL覆盖图的转储。在日志中，您应该看到pre_fuzz_handler和post_fuzz_handler正好运行了10次，并且您的输入文件在每次迭代中都处于打开状态。记下用于设置-coverage_module标志的已加载模块的列表。请注意，您必须在日志文件中使用与模块名称相同的值（不区分大小写）。

现在你应该准备好模糊目标。首先，确保afl-fuzz.exe和winafl.dll都在当前目录中。如前所述，Windows上afl-fuzz的命令行是：
afl-fuzz [afl options] -- [instrumentation options] -- target_cmd_line
请参阅上面的支持AFL和仪器选项列表。

在AFL选项中，您必须通过新的-D选项指定DynamoRIO二进制文件目录。您需要将DynamoRIO和winafl.dll构建（32与64位）匹配到目标二进制文件。-t（超时）选项对于WinAFL来说是强制性的，因为执行时间可能在仪器使用方面有很大的不同，所以依靠自动确定的值并不是一个好主意。

您可以使用与步骤2中相同的WinAFL选项，但请记住排除-debug标志，您可能需要增加迭代计数。

和Linux中的afl-fuzz一样，你可以用@@替换目标二进制文件的输入文件参数。

示例命令行如下所示：

afl-fuzz.exe -i in -o out -D C:\work\winafl\DynamoRIO\bin64 -t 20000 --
-coverage_module gdiplus.dll -coverage_module WindowsCodecs.dll
-fuzz_iterations 5000 -target_module test_gdiplus.exe -target_offset 0x1270
-nargs 2 -- test_gdiplus.exe @@
或者，如果test_gdiplus.exe的符号可用，则可以使用-target_method而不是-target_offset，如下所示：

afl-fuzz.exe -i in -o out -D C:\work\winafl\DynamoRIO\bin64 -t 20000 --
-coverage_module gdiplus.dll -coverage_module WindowsCodecs.dll
-fuzz_iterations 5000 -target_module test_gdiplus.exe -target_method main
-nargs 2 -- test_gdiplus.exe @@
而已。快乐fuzzing！

我的目标如何在WinAFL下运行

当你选择一个目标函数和模糊应用程序时，会发生以下情况：

你的目标正常运行，直到你的目标函数达到。
WinAFL开始记录报道
你的目标函数运行直到返回
WinAFL报告覆盖范围，重写输入文件和修补程序EIP，以便执行跳回步骤2
目标函数运行达到指定的迭代次数后，目标进程将被终止并重新启动。请注意，在目标函数返回后运行的任何内容都不会到达。
如何选择一个目标函数

目标函数应该在其生命周期中做这些事情：

打开输入文件。这需要与目标函数一起发生，以便您可以在每个迭代中读取一个新的输入文件，因为输入文件在目标函数运行之间被重写）。
解析它（这样就可以测量文件解析的覆盖率）
关闭输入文件。这很重要，因为如果输入文件没有关闭，WinAFL将不能重写它。
正常返回（所以WinAFL可以“捕获”这个返回和重定向执行，通过ExitProcess（）等“返回”将不起作用）
语料库最小化

WinAFL包含winafl-cmin.py中的afl-cmin的Windows端口。请运行以下命令查看选项和用法示例：

D:\Codes\winafl>python winafl-cmin.py -h
[...]
Examples of use:
 * Typical use
  winafl-cmin.py -D D:\DRIO\bin32 -t 100000 -i in -o minset -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@

 * Dry-run, keep crashes only with 4 workers with a working directory:
  winafl-cmin.py -C --dry-run -w 4 --working-dir D:\dir -D D:\DRIO\bin32 -t 10000 -i in -i C:\fuzz\in -o out_mini -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@

 * Read from specific file
  winafl-cmin.py -D D:\DRIO\bin32 -t 100000 -i in -o minset -f foo.ext -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@

 * Read from specific file with pattern
  winafl-cmin.py -D D:\DRIO\bin32 -t 100000 -i in -o minset -f prefix-@@-foo.ext -covtype edge -coverage_module m.dll -target_module test.exe -target_method fuzz -nargs 2 -- test.exe @@

 * Typical use with static instrumentation
   winafl-cmin.py -Y -t 100000 -i in -o minset -- test.exe @@
winafl-cmin.py

通过syzygy静态工具二进制

背景

syzygy提供了一个能够以 完整的PDB 分解 PE32二进制文件的框架。分解一个二进制是用来表示接收输入一个PE32二进制和它的PDB，分析和分解每一个功能，每一个代码/数据块以安全的方式，并将其呈现给变换“通过”。转换过程是一个以某种方式转换二进制的类; 例如，syzyasan 转换就是一个例子。一旦通道转换了二进制文件，它就会将其传回到能够重新链接输出二进制文件的框架（当然，应用了转换）。

AFL仪器已经被添加到syzygy的instrumenter允许用户静态仪器私人符号PE32二进制文件。

在IDA下的afl仪器

如何编写目标函数

为了准备你的目标，你需要先包含afl-staticinstr.h然后__afl_persistent_loop像在test_static.cpp：

int fuzz(int argc, char**argv) {
  while(__afl_persistent_loop()) {
    test(argc, argv);
  }
  return 1;
}
__afl_persistent_loop的实现生活中afl-staticinstr.c，基本上再现了什么DynamoRIO插件正在做pre_fuzz_handler和post_fuzz_handler。“如何选择目标函数”中提到的每个点也适用于此。

您可以使用该标志调用AFL工具，-Y以便在模糊，语料库最小化或测试用例最小化期间​​启用静态检测模式：

afl-fuzz.exe -Y -i minset -o o1 -t 10000 -- -fuzz_iterations 5000 -- test_static.instr.exe @@
winafl-cmin.py -Y -t 100000 -i in -o minset -- test_static.instr.exe @@
afl-tmin.exe -Y -i ..\testcases\tests\big.txt -o big.min.txt -- test_static.instr.exe @@
建立instrument.exe

为了方便起见，bin32目录中包含了确认可以与WinAFL一起使用的instrument.exe版本。如果你想自己建立它，请按照下面的说明。

为了克隆syzygy的仓库，你可以按照这里列出的说明：SyzygyDevelopmentGuide。一旦你拥有depot_tools和存储库克隆，你可以像这样编译instrument.exe：

C:\syzygy\src>ninja -C out\Release instrument
目前推荐的修订版本是190dbfe（v0.8.32.0）。

注册msdia140

msdia140.dll通过执行以下命令，确保在您的系统上注册：

regsvr32 /s msdia140.dll
测试一个目标

您的目标二进制文件必须使用/ PROFILE连接器标志进行编译，以生成完整的PDB。

C:\>instrument.exe --mode=afl --input-image=test_static.exe --output-image=test_static.instr.exe --force-decompose --multithread --cookie-check-hook
[0718/224840:INFO:application_impl.h(46)] Syzygy Instrumenter Version 0.8.32.0 (0000000).
[0718/224840:INFO:application_impl.h(48)] Copyright (c) Google Inc. All rights reserved.
[0718/224840:INFO:afl_instrumenter.cc(116)] Force decomposition mode enabled.
[0718/224840:INFO:afl_instrumenter.cc(122)] Thread-safe instrumentation mode enabled.
[0718/224840:INFO:afl_instrumenter.cc(128)] Cookie check hook mode enabled.
[...]
[0718/224840:INFO:security_cookie_check_hook_transform.cc(67)] Found a __report_gsfailure implementation, hooking it now.
[0718/224840:INFO:add_implicit_tls_transform.cc(77)] The binary doesn't have any implicit TLS slot defined, injecting one.
[0718/224840:INFO:afl_transform.cc(144)] Placing TLS slot at offset +4.
[0718/224840:INFO:afl_transform.cc(237)] Code Blocks instrumented: 92 (95%)
[...]
[0718/224841:INFO:pe_relinker.cc(240)] PE relinker finished.

C:\>test_static.instr.exe test
Persistent loop implementation by <0vercl0k@tuxfamily.org>
Based on WinAFL by <ifratric@google.com>
[+] Found a statically instrumented module: test_static.instr.exe (multi thread mode).
[-] Not running under afl-fuzz.exe.
[+] Enabling the no fuzzing mode.
Error opening file
可用选项

--config=<path>         Specifies a JSON file describing, either
                        a whitelist of functions to instrument or
                        a blacklist of functions to not instrument.
--cookie-check-hook     Hooks __security_cookie_check.
--force-decompose       Forces block decomposition.
--multithread           Uses a thread-safe instrumentation.
config：JSON文件允许您将检测范围缩小到一组函数名称。您可以使用白名单或黑名单功能。将黑名单函数生成可变行为可能非常有用。

cookie-check-hook：这可以确保/ GS cookie检查函数生成我们的VEH可以捕获的异常。Failfast异常不能被任何EH机制in-proc 捕获，所以我们利用 syzygy来重写cookie检查函数，以便产生 一个我们可以捕获的异常。

force-decompose：这个开关允许你重写syzygy在评估一个函数是否安全分解的时候做出的决定。如果你打开这个标志，你的仪器覆盖率将会更高，但是你最终可能会以一种奇怪的方式崩溃。只有在你知道你在做什么的情况下才能使用。

多线程：此开关打开线程安全的仪器。与单线程仪器的主要区别在于__afl_prev_loc将存储在TLS插槽中。

限制

拥有巨大的权力是很重要的责任，所以这里是限制的列表：

仪表仅限于具有完整PDB符号的PE 32位二进制文​​件（链接器标志/PROFILE）。

syzygy定义了能够安全地分解块的几个前提条件 ; 这也许可以解释为什么你的仪表比例很低。

常问问题

Q: WinAFL reports timeouts while processing initial testcases.
A: You should run your target in debug mode first (-debug flag) and only
   run WinAFL once you get a message in the debug log that everything
   appears to be running normally.

Q: WinAFL runs slower than expected
A: This can commonly happen for several reasons
 - Your target function loads a dll for every iteration. This causes
   DynamoRIO to translate the same code for every iteration which causes
   slowdowns. You will be able to see this in the debug log. To
   resolve, select (or write) your target function differently.
 - Your target function does not close the input file properly, which
   causes WinAFL to kill the process in order to rewrite it. Please refer
   to 6) for what a target function should look like.

Q: Can I fuzz DLLs with WinAFL
A: Yes, if you can write a harness that loads a library and runs some
   function within. Write your target function according to "How to select
   a target function" and for best performance, load the dll outside of
   your target function (see the previous question).

Q: Can I fuzz GUI apps with WinAFL
A: Yes, provided that
 - There is a target function that behaves as explained in "How to select
   a target function"
 - The target function is reachable without user interaction
 - The target function runs and returns without user interaction
 If these conditions are not satisfied, you might need to make custom changes
 to WinAFL and/or your target.
