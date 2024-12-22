# Bisecting a Bug in Apache NuttX RTOS (Git Bisect)

📝 _31 Jan 2024_

![TODO](https://lupyuen.github.io/images/bisect-title.jpg)

2 Weeks Ago: We spoke of a [__Runtime Bug__](TODO) in __Apache NuttX RTOS__. We think that the __Breaking Commit__ falls somewhere between these __"Good" and "Bad" Commits__...

| | |
|:------------|:---------|
| __Good Commit__ <br> _DD MMM YYYY_ | NuttX runs OK  <br> _1234abcd_ TODO
| __Bad Commit__ <br> _DD MMM YYYY_ | NuttX fails to run <br> _1234abcd_ TODO

That's [__TODO Commits__](TODO). Which is the Breaking Commit?

_We could Rewind Each Commit and test?_

We could rewind and retest TODO Commits for [__Compile Errors__](TODO). But it's probably too slow for __Runtime Errors__.

We have a quicker way: __Git Bisect__!

TODO

# Automated Bisect

_What's this Git Bisect?_

Remember [__Binary Chop__](TODO)?

> "I'm thinking of a number from 1 to TODO <br> To guess my number: <br> Ask me TODO yes-no questions"

[__Git Bisect__](TODO) works the same way, but for __Git Commits__...

- Our __Breaking Commit__ is one of ??? Commits

- Git Bisect shall __Pick the Middle Commit__ and ask: "Is this a Good Commit or Bad Commit?"

- Repeat until we discover the __Breaking Commit__

_Is it automated?_

Yep Git Bisect will gleefully seek the Breaking Commit on its own... Assuming that we provide a Script to __Assess the Goodness / Badness__ of a NuttX Commit...

TODO: Simple Script

[(Or do it manually)](TODO)

This is how we start Git Bisect...

TODO: Git Bisect Script

Let's study the outcome...

TODO: Pic of Simulated Git Bisect

# Simulate The Git Bisect

_What just happened in Git Bisect?_

- We told Git Bisect that Commit #`TODO` is Good and Commit #`TODO` is Bad

- Git Bisect picked the __Middle Commit__ #`TODO`

- And discovered that __Commit #`TODO` is TODO__ (via our script)

- Then it continued bisecting. Assessing Commit #`TODO` (TODO), #`TODO`(TODO), #`TODO` (TODO)...

- Finally deducing that Commit #`TODO` is the __Breaking Commit__

This works fine for our (randomised) __Simulated Git Bisect__. Now we do it for real...

# Continuous Integration Test

_Will Git Bisect work for Real-Life NuttX?_

From our [__Bug Report__](TODO): NuttX fails the __Continuous Integration Test__ (CI Test) for RISC-V QEMU.

TODO: CI Test Log

This happens inside the CI Job risc-v-TODO, which we can run with __Docker Engine__...

TODO: Run CI Test with Docker

Thus this becomes our Git Bisect Script (that assesses "Goodness" vs "Badness")

TODO: Git Bisect Script

We run this...

TODO: Pic of Git Bisect #1

# Git Bisect For Real

_What just happened in Git Bisect?_

- We told Git Bisect that Commit #`TODO` is Good and Commit #`TODO` is Bad

- Git Bisect picked the __Middle Commit__ #`TODO`

- And discovered that __Commit #`TODO` is TODO__ (via our script)

- Then it continued bisecting. Assessing Commit #`TODO` (TODO), #`TODO`(TODO), #`TODO` (TODO)...

- Finally deducing that Commit #`TODO` is the __Breaking Commit__

TODO

# Git Bisect Gets Quirky

_Did Git Bisect find the correct Breaking Commit?_

To be absolutely sure: We run Git Bisect __one more time__...

TODO

# TODO

Number the commits

Commit #`123`

Commit #`456`

Why Git Bisect? Because each test runs for 1 hour!

TODO

# Git Bisect on Original Bug

## NuttX Commits

https://github.com/apache/nuttx/issues/14808

NuttX Commit #1: Earlier NuttX Repo Commits were OK: https://github.com/apache/nuttx/tree/6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c

NuttX Commit #2: Later NuttX Repo Commits were OK: https://github.com/apache/nuttx/tree/656883fec5561ca91502a26bf018473ca0229aa4

NuttX Commit #3: Belated Commits fail at test_ltp_interfaces_pthread_barrierattr_init_2_1: https://github.com/apache/nuttx/issues/14808#issuecomment-2518119367

## Apps Commits

Earlier NuttX Apps Commits were OK: https://github.com/apache/nuttx-apps/tree/1c7a7f7529475b0d535e2088a9c4e1532c487156

Later NuttX Apps Commits were ???: https://github.com/apache/nuttx-apps/tree/3c4ddd2802a189fccc802230ab946d50a97cb93c

Belated NuttX Apps Commits were ???

```bash
## TODO: Install Docker Engine
## https://docs.docker.com/engine/install/ubuntu/

## TODO: For WSL, we may need to install Docker on Native Windows
## https://github.com/apache/nuttx/issues/14601#issuecomment-2453595402

## TODO: Bisect CI Job
job=risc-v-05

## NuttX Commit #1 (14 Nov 2024): Runs OK
## nuttx_hash=6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c

## NuttX Commit #2: Runs OK
## nuttx_hash=656883fec5561ca91502a26bf018473ca0229aa4

## NuttX Commit #3 (4 Dec 2024): Fails at test_ltp_interfaces_pthread_barrierattr_init_2_1
## https://github.com/apache/nuttx/issues/14808#issuecomment-2518119367
## test_open_posix/test_openposix_.py::test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED   [ 17%]
nuttx_hash=79a1ebb9cd0c13f48a57413fa4bc3950b2cd5e0b

## Apps Commit #1: Runs OK
apps_hash=1c7a7f7529475b0d535e2088a9c4e1532c487156

## Apps Commit #2: ???
## apps_hash=1c7a7f7529475b0d535e2088a9c4e1532c487156

## Apps Commit #3: ???
## https://github.com/apache/nuttx/issues/14808#issuecomment-2518119367
## apps_hash=ce217b874437b2bd60ad2a2343442506cd8b50b8

sudo ./run-job-bisect.sh $job $nuttx_hash $apps_hash
```

[NuttX Commit #1: Runs OK. nuttx_hash=6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c](https://gist.github.com/lupyuen/89759c53accbf6caa717b39fd5e69bae)

[NuttX Commit #2: Runs OK. nuttx_hash=656883fec5561ca91502a26bf018473ca0229aa4](https://gist.github.com/lupyuen/e22cd208bd9ed3e36e59de2b44bb85ef)

[NuttX Commit #3: Fails at test_ltp_interfaces_pthread_barrierattr_init_2_1. nuttx_hash=79a1ebb9cd0c13f48a57413fa4bc3950b2cd5e0b](https://gist.github.com/lupyuen/27cb7f5359bc0a8176db9815ba8b162a)

Assume will terminate in 1 hour! Actually terminates in 30 mins. Change this for your machine!

Press Ctrl-C very carefully, don't crash Docker!

How many commits between 14 Nov and 4 Dec?

Now that we can bisect reliably and automatically: Shall we do this for All Failed Builds?

NuttX Hash vs Apps Hash

But NuttX Commit might not compile with Apps Commit, must be compatible

Maybe return special exit code 125 if can't compile

Inconsistent CI Test?

[run-job-bisect.sh risc-v-05 94a2ce3641213cc702abc5c17b0f81a50c714a2e 1c7a7f7529475b0d535e2088a9c4e1532c487156 / fails at test_ltp_interfaces_sigaction_12_35](https://gist.github.com/lupyuen/7c9fa7d30fed3fe73ffeb7e7f1ddd0fb)

[git bisect: good 6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c / bad 79a1ebb9cd0c13f48a57413fa4bc3950b2cd5e0b](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d)

[second run of git bisect: good 6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c / bad 79a1ebb9cd0c13f48a57413fa4bc3950b2cd5e0b](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493)

good: [94a2ce3641213cc702abc5c17b0f81a50c714a2e] tools/gdb: need to switch back to inferior 1
vs
bad: [94a2ce3641213cc702abc5c17b0f81a50c714a2e] tools/gdb: need to switch back to inferior 1

Let it simmer overnight (probably 7 hours, like my Bean Stew)

Locoroco merging into big bubbles

Did git bisect find the breaking commit? 

Erm not quite.

Always run twice 

That's 2 bean stews!

_So it's like travelling back in time, changing something in history, and the future changes?

Um.somegthing like thst

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

TODO: Search disassembly for ltp_interfaces_pthread_barrierattr_init_2_1

```text
8006642c <ltp_interfaces_pthread_barrierattr_init_2_1_main>:
ltp_interfaces_pthread_barrierattr_init_2_1_main():
/root/apps/testing/ltp/ltp/testcases/open_posix_testsuite/conformance/interfaces/pthread_barrierattr_init/2-1.c:27
#include "posixtest.h"

#define BARRIER_NUM 100

int main(void)
{
8006642c:	7149                	add	sp,sp,-368
8006642e:	72fd                	lui	t0,0xfffff
/root/apps/testing/ltp/ltp/testcases/open_posix_testsuite/conformance/interfaces/pthread_barrierattr_init/2-1.c:34
	pthread_barrierattr_t ba;
	pthread_barrier_t barriers[BARRIER_NUM];
	int cnt;
```

Which points to https://github.com/apache/nuttx-apps/tree/master/testing/ltp

```text
sudo docker cp nuttx:/root/apps/testing/ltp/Kconfig /tmp
nano /tmp/Kconfig
sudo docker cp /tmp/Kconfig nuttx:/root/apps/testing/ltp/Kconfig
```

Change:
```text
config TESTING_LTP_STACKSIZE
	int "Linux Test Project stack size"
	default 4096
```
To:
```text
config TESTING_LTP_STACKSIZE
	int "Linux Test Project stack size"
	default 8192
```
And copy to docker.

Re-run:

```text
cd /root/nuttx
make distclean
cd tools/ci
./cibuild.sh -c -A -N -R testlist/risc-v-05.dat 
[ Wait for it to fail. Then press Ctrl-C a few times to stop it ]
cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*
```

Or:

```text
sudo docker exec \
  -it \
  nuttx \
  /bin/bash
cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*
```

Fixed yay! [testing/ltp: Increase Stack Size](https://github.com/apache/nuttx-apps/pull/2888)

# Bisect Run

https://git-scm.com/docs/git-bisect#_bisect_run

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
