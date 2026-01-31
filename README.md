# Retrocast
Retrocast is a program for filtering internet traffic on your computer based on time and modifying website layouts.

Hello everyone! I have a project—UI.exe with a couple of compiled scripts (Rust, cpp) and Python scripts. The idea is to:

1) intercept traffic on a personal computer; —>
2) decrypt it and read payloads for DATES; —>
3) block incoming internet packets if they contain invalid dates; —>
4) also, the project transforms (really tries to) website layouts, giving them a vintage look using archived snapshots (injecting and modifying packet contents).

Over the past three years of learning programming, I haven't really advanced beyond Python—I admit, when working with Rust, C++, and other tools, I often had to resort to AI when compiling them into DLLs and EXEs.

In addition to the original code, the project contains third-party open-source projects—WinDivert (https://reqrypt.org/windivert.html) and mitmproxy (https://www.mitmproxy.org)—that intercept, read, and inject packets. Snapshots of archived versions of websites (Wikipedia, for example) were downloaded from Archive.org (https://web.archive.org).

Time filtering and snapshot injection are still fairly crude. I tested the project on my computer and in my browser, but I can't be sure that it will produce the same successful results for you due to the many different software requirements.

You may find the project interesting and intriguing, BUT:

— The project in its current state is NOT INTENDED for regular use, or for personal tasks—the project exists ONLY FOR TESTING;

— The project is required to save TXT logs in the program folder. These are useful for viewing results and errors, BUT THEY CAN AND MOST LIKELY WILL CONTAIN YOUR OWN TRAFFIC.

Cautions:
— Install and run the project on a VM, as I'm not sure of its stability;
— Do not test the project on personal, sensitive traffic. If you wish to share the log results, carefully ensure they do not contain your data;
— Remember to delete the logs when you no longer need them;
— Read the README.md file inside the program folder for more complete warnings and setup instructions.

I understand that dll and executable files from the internet may not be trustworthy; their source code files (\source) are also available on GitHub. You can compile them yourself on your computer, then compare the hashes of your builds with mine. IDE, compiler, and other versions:

CMake:
cmake .. -G "Visual Studio 17 2022" -A x64
-- Selecting Windows SDK version 10.0.26100.0 to target Windows 10.0.19044.
-- The CXX compiler identification is MSVC 19.44.35222.0
-- Check for working CXX compiler: C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe - skipped

MSBuild:
MSBuild version 17.14.23+b0019275e for .NET Framework

Cargo (Rust):
cargo --version
cargo 1.92.0 (344c4567c 2025-10-21)

>> cargo build --release
   Compiling proc-macro2 v1.0.106
   Compiling unicode-ident v1.0.22
   Compiling quote v1.0.44
   Compiling autocfg v1.5.0
   Compiling memchr v2.7.6
   Compiling serde_core v1.0.228
   Compiling num-traits v0.2.19
   Compiling winapi v0.3.9
   Compiling zmij v1.0.17
   Compiling syn v2.0.114
   Compiling aho-corasick v1.1.4
   Compiling serde_json v1.0.149
   Compiling regex-syntax v0.8.8
   Compiling serde v1.0.228
   Compiling regex-automata v0.4.13
   Compiling serde_derive v1.0.228
   Compiling cfg-if v1.0.4
   Compiling windows-link v0.2.1
   Compiling itoa v1.0.17
   Compiling chrono v0.4.43
   Compiling encoding_rs v0.8.35
   Compiling named_pipe v0.4.1
   Compiling regex v1.12.2

Let me know if I missed some software version here.

https://github.com/Pop-a-ball/Retrocast
