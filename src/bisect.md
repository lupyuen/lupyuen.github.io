# TODO (Git Bisect)

📝 _31 Jan 2024_

![TODO](https://lupyuen.github.io/images/bisect-title.jpg)

TODO

# TODO


Current Failure: [rv-virt:citest fails with Load Access Fault at ltp_interfaces_pthread_barrierattr_init_2_1 (risc-v-05)](https://github.com/apache/nuttx/issues/15170)

Previous Failure: [rv-virt/citest: test_hello or test_pipe failed](https://github.com/apache/nuttx/issues/14808)

Due to: [arch/toolchain: Add toolchain gcc](https://github.com/apache/nuttx/pull/14779)

Fixed by: [rv-virt/citest: Increase init task stack size to 3072](https://github.com/apache/nuttx/pull/15165)

TODO: Test Git Bisect

```bash
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
cd nuttx

git bisect start
git bisect bad HEAD
git bisect good 656883fec5561ca91502a26bf018473ca0229aa4
git bisect run my_test_script.sh

https://git-scm.com/docs/git-bisect
$ git bisect visualize
$ git bisect visualize --stat
$ git bisect log
```

https://github.com/lupyuen/nuttx-bisect/blob/main/run.sh

https://github.com/lupyuen/nuttx-bisect/blob/main/my-test-script.sh

[git bisect run my-test-script.sh](https://gist.github.com/lupyuen/e822323378e09ae3c24a41c5f42abfd0)

TODO: With Docker

```bash
sudo docker run \
  -it \
  --name nuttx \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash
cd
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/$(git rev-parse HEAD) ; popd
pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/$(git rev-parse HEAD) ; popd
cd nuttx/tools/ci
./cibuild.sh -c -A -N -R testlist/risc-v-05.dat 
[ Wait for it to fail. Then press Ctrl-C a few times to stop it ]
cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*
```

TODO: Check size

```
## https://github.com/google/bloaty
$ /tools/bloaty/bin/bloaty /root/nuttx/nuttx 
    FILE SIZE        VM SIZE    
 --------------  -------------- 
  46.1%  6.80Mi   0.0%       0    .debug_info
  17.1%  2.53Mi   0.0%       0    .debug_line
   8.6%  1.26Mi   0.0%       0    .debug_abbrev
   6.6%  1000Ki   0.0%       0    .debug_loclists
   6.2%   941Ki  64.9%   941Ki    .text
   5.1%   772Ki   0.0%       0    .debug_str
   2.5%   381Ki  26.3%   381Ki    .rodata
   1.8%   277Ki   0.0%       0    .debug_frame
   1.7%   254Ki   0.0%       0    .symtab
   1.2%   174Ki   0.0%       0    .strtab
   1.1%   166Ki   0.0%       0    .debug_rnglists
   1.1%   164Ki   0.0%       0    .debug_line_str
   0.0%       0   8.1%   118Ki    .bss
   0.8%   114Ki   0.0%       0    .debug_aranges
   0.1%  8.31Ki   0.6%  8.27Ki    .data
   0.0%  5.00Ki   0.1%     858    [104 Others]
   0.0%  3.89Ki   0.0%       0    [Unmapped]
   0.0%  2.97Ki   0.0%       0    .shstrtab
   0.0%     296   0.0%     256    .srodata.cst8
   0.0%     196   0.0%       0    [ELF Headers]
   0.0%     144   0.0%     104    .sdata.called
 100.0%  14.8Mi 100.0%  1.42Mi    TOTAL

$ /tools/bloaty/bin/bloaty /root/nuttx/nuttx -d compileunits
bloaty: Unknown ELF machine value: 243'

Fuchsia supports it:
https://fuchsia.googlesource.com/third_party/bloaty/+/53360fd9826a417671a92386306745bfd5755f21%5E1..53360fd9826a417671a92386306745bfd5755f21/

cd
git clone https://fuchsia.googlesource.com/third_party/bloaty
cd bloaty
cmake -B build -G Ninja -S .
cmake --build build
cd /root/nuttx
/root/bloaty/build/bloaty nuttx -d compileunits,segments,sections,symbols

https://github.com/lupyuen/nuttx-bisect/releases/download/main-1/bloaty.log
```

TODO: Dump the disassembly

```text
## Dump the disassembly to nuttx.S
cd /root/nuttx
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1
sudo docker cp nuttx:/root/nuttx/nuttx.S .

https://github.com/lupyuen/nuttx-bisect/releases/download/main-1/nuttx.S
```

https://git-scm.com/docs/git-bisect#_bisect_run

Bisect run

If you have a script that can tell if the current source code is good or bad, you can bisect by issuing the command:

$ git bisect run my_script arguments

Note that the script (my_script in the above example) should exit with code 0 if the current source code is good/old, and exit with a code between 1 and 127 (inclusive), except 125, if the current source code is bad/new.

Any other exit code will abort the bisect process. It should be noted that a program that terminates via exit(-1) leaves $? = 255, (see the exit(3) manual page), as the value is chopped with & 0377.

The special exit code 125 should be used when the current source code cannot be tested. If the script exits with this code, the current revision will be skipped (see git bisect skip above). 125 was chosen as the highest sensible value to use for this purpose, because 126 and 127 are used by POSIX shells to signal specific error status (127 is for command not found, 126 is for command found but not executable—​these details do not matter, as they are normal errors in the script, as far as bisect run is concerned).

You may often find that during a bisect session you want to have temporary modifications (e.g. s/#define DEBUG 0/#define DEBUG 1/ in a header file, or "revision that does not have this commit needs this patch applied to work around another problem this bisection is not interested in") applied to the revision being tested.

To cope with such a situation, after the inner git bisect finds the next revision to test, the script can apply the patch before compiling, run the real test, and afterwards decide if the revision (possibly with the needed patch) passed the test and then rewind the tree to the pristine state. Finally the script should exit with the status of the real test to let the git bisect run command loop determine the eventual outcome of the bisect session.

# What's Next

TODO

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/bisect.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/bisect.md)
