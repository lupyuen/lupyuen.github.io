# Failing a Continuous Integration Test for Apache NuttX RTOS (QEMU RISC-V)

📝 _30 Dec 2024_

![TODO](https://lupyuen.github.io/images/ci7-title.jpg)

TODO: Bothersome bug flagged by NuttX Dashboard every day since a month ago

![TODO](https://lupyuen.github.io/images/ci7-dashboard.png)

```text
Configuration/Tool: rv-virt/citest
test_cmocka      PASSED
test_hello       PASSED
test_helloxx     FAILED
test_pipe        FAILED
test_usrsocktest FAILED
[...Failing all the way...]
```

[(See the __Complete Log__)](https://github.com/NuttX/nuttx/actions/runs/12263479539/job/34215189342#step:7:88)

Reported one month ago: ["[BUG] rv-virt/citest: test_hello or test_pipe failed"](https://github.com/apache/nuttx/issues/14808)

The bug stops here! (OK maybe not today)

# Run the CI Test

__Thanks to Docker:__ We can run __CI Test _risc-v-05___ on our Ubuntu PC...

[(Steps for __macOS Arm64__)](TODO)

```bash
## Start the NuttX Docker Image
## Name the Docker Container as `nuttx`
sudo docker run \
  -it \
  --name nuttx \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash

## Inside Docker: Checkout the NuttX Repo and NuttX Apps
cd
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/$(git rev-parse HEAD) ; popd
pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/$(git rev-parse HEAD) ; popd

## Run CI Test risc-v-05 inside Docker Container
cd nuttx/tools/ci
./cibuild.sh \
  -c -A -N -R \
  testlist/risc-v-05.dat 
```

Docker will build _rv-virt:citest_ and start the CI Test...

```text
Configuration/Tool: rv-virt/citest
python3 -m pytest -m 'qemu or rv_virt' ./ -B rv-virt -P /root/nuttx -L /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu -R qemu -C --json=/root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/pytest.json
test_cmocka      PASSED
test_hello       PASSED
test_helloxx     FAILED
test_pipe        FAILED
test_usrsocktest FAILED
[...Failing all the way...]
```

Which is totally unhelpful. Why is it failing?

[(See the __Complete Log__)](https://gist.github.com/lupyuen/c59a642a3f3c5934ec53d5d72dd6e01d)

# Snoop the CI Test

To find out what went wrong: We connect to the Docker Container and snoop the __Background Processes__...

```bash
## Connect to the Running Docker Container
sudo docker exec \
  -it \
  nuttx \
  /bin/bash

## What's running now?
ps aux | more
```

A-ha! We see NuttX running on QEMU RISC-V...

```bash
## We started this...
cibuild.sh -c -A -N -R testlist/risc-v-05.dat

## Which calls testbuild.sh...
/root/nuttx/tools/testbuild.sh -A -N -R -j 24 -e -W

## Which calls citest/run...
/root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/run

## Which calls pytest...
python3 -m pytest -m 'qemu or rv_virt' ./ -B rv-virt -P /root/nuttx -L /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu -R qemu -C --json=/root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/pytest.json

## Which boots NuttX on QEMU RISC-V...
qemu-system-riscv32 -M virt -bios ./nuttx -nographic -drive index=0,id=userdata,if=none,format=raw,file=./fatfs.img -device virtio-blk-device,bus=virtio-mmio-bus.0,drive=userdata
  | tee /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/rv-virt_20241211_063532.log

## And tees the output to the above Log File
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/399d2ba7d964ba88cdbeb97f64778a0e)

# Dump the CI Log File

From above: We see that everything goes into this __CI Test Log File__...

```bash
## Dump the CI Test Log File (e.g. rv-virt_20241211_063532.log)
$ cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*

NuttShell (NSH) NuttX-12.7.0
nsh> cmocka --skip test_case_posix_timer|test_case_oneshot|write_default|read_defaulCmocka Test Start.
Cmocka Test Completed.

nsh> ps
  PID GROUP PRI POLICY   TYPE    NPX STATE    EVENT     SIGMASK            STACK    USED FILLED COMMAND
    0     0   0 FIFO     Kthread   - Ready              0000000000000000 0001952 0000844  43.2%  Idle_Task
    1     0 224 RR       Kthread   - Waiting  Semaphore 0000000000000000 0001904 0000524  27.5%  hpwork 0x8014b1f4 0x8014b220
    2     0 100 RR       Kthread   - Waiting  Semaphore 0000000000000000 0001896 0000508  26.7%  lpwork 0x8014b1b0 0x8014b1dc
riscv_exception: EXCEPTION: Load access fault. MCAUSE: 00000005, EPC: 80008bfe, MTVAL: 01473e00
riscv_exception: PANIC!!! Exception = 00000005
dump_assert_info: Current Version: NuttX  12.7.0 5607eece84 Dec 11 2024 06:34:00 risc-v
dump_assert_info: Assertion failed panic: at file: common/riscv_exception.c:131 task: nsh_main process: nsh_main 0x8000a806
up_dump_register: EPC: 80008bfe
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/399d2ba7d964ba88cdbeb97f64778a0e)

Hmmm this looks super interesting... NuttX "__`ps`__" crashes inside QEMU!

# Test NuttX on QEMU RISC-V

_What if we test rv-virt:citest ourselves on QEMU?_

This is how we compile _rv-virt:citest_ inside Docker...

```bash
## Compile rv-virt:citest inside Docker
sudo docker run \
  -it \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash
cd
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/$(git rev-parse HEAD) ; popd
pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/$(git rev-parse HEAD) ; popd
cd nuttx
tools/configure.sh rv-virt:citest
make -j
```

Now we boot __NuttX on QEMU__...

```bash
$ qemu-system-riscv32 -M virt -bios ./nuttx -nographic

NuttShell (NSH) NuttX-12.7.0
nsh> uname -a
NuttX  12.7.0 5607eece84 Dec 11 2024 07:05:48 risc-v rv-virt

nsh> ps
  PID GROUP PRI POLICY   TYPE    NPX STATE    EVENT     SIGMASK            STACK    USED FILLED COMMAND
    0     0   0 FIFO     Kthread   - Ready              0000000000000000 0001952 0000908  46.5%  Idle_Task
    1     0 224 RR       Kthread   - Waiting  Semaphore 0000000000000000 0001904 0000508  26.6%  hpwork 0x8014b1e4 0x8014b210
    2     0 100 RR       Kthread   - Waiting  Semaphore 0000000000000000 0001896 0000508  26.7%  lpwork 0x8014b1a0 0x8014b1cc
riscv_exception: EXCEPTION: Load access fault. MCAUSE: 00000005, EPC: 80008bfe, MTVAL: 01473e00
riscv_exception: PANIC!!! Exception = 00000005
dump_assert_info: Current Version: NuttX  12.7.0 5607eece84 Dec 11 2024 07:05:48 risc-v
dump_assert_info: Assertion failed panic: at file: common/riscv_exception.c:131 task: nsh_main process: nsh_main 0x8000a806
up_dump_register: EPC: 80008bfe
```

Yep we can reproduce the bug using plain old __Make and QEMU__. No need for CI Test Script!

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4ec0df33c2b4b569c010fade5f471940)

# TODO

Filipe Cavalcanti wrote an excellent article on Pytest in NuttX: ["Testing applications with Pytest and NuttX"](https://developer.espressif.com/blog/pytest-testing-with-nuttx/)

pytest

expect

Pytest to plain expect script 

TDD 

# What's Next

TODO

Next Article: We'll chat about an __Experimental Mastodon Server__ for NuttX Continuous Integration.

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci7.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci7.md)

# Appendix: CI Test on macOS Arm64

TODO: This is how we replicate CI Test on macOS Apple Silicon

```bash
## Pytest
cd $HOME/nuttx-build-farm
./run-job-macos.sh risc-v-05
exit

# run-job-macos.sh risc-v-05
# https://gist.github.com/lupyuen/210b6a33d6c51293ad985247ecfc47a0

# run-job-macos.sh risc-v-05: rv-virt_20241210_190204.log
# https://gist.github.com/lupyuen/6bd3b60a93ddac13e20c825f8a171ed6

# ps works OK on nsh 32-bit
# https://gist.github.com/lupyuen/4d69faccde982ad236f45f93d6fb1f17#file-special-qemu-riscv-nsh-log-L257

# $ ps aux | grep qemu
# qemu-system-riscv32 -M virt -bios ./nuttx -nographic -drive index=0,id=userdata,if=none,format=raw,file=./fatfs.img -device virtio-blk-device,bus=virtio-mmio-bus.0,drive=userdata
# tee /private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/rv-virt_20241210_184405.log
# /bin/bash -c qemu-system-riscv32 -M virt -bios ./nuttx -nographic -drive index=0,id=userdata,if=none,format=raw,file=./fatfs.img -device virtio-blk-device,bus=virtio-mmio-bus.0,drive=userdata | tee /private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/rv-virt_20241210_184405.log
# /opt/homebrew/Cellar/python@3.13/3.13.0_1/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python -m pytest -m qemu or rv_virt ./ -B rv-virt -P /private/tmp/run-job-macos/nuttx -L /private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu -R qemu -C --json=/private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/pytest.json
# bash /private/tmp/run-job-macos/nuttx/../nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/run

## ls -l /tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu
## cp /tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/* .
## rv-virt_20241210_175024.log
## python3 -m pytest -m qemu or rv_virt ./ -B rv-virt -P /private/tmp/run-job-macos/nuttx -L /private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu -R qemu -C --json=/private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/pytest.json
## python3 \
##   -m pytest \
##   -m qemu or rv_virt ./ \
##   -B rv-virt \
##   -P /private/tmp/run-job-macos/nuttx \
##   -L /private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu \
##   -R qemu \
##   -C \
##   --json=/private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/pytest.json
## cd /private/tmp/run-job-macos/nuttx/tools/ci/testrun/script
## python3 -m pytest -m 'qemu or rv_virt' ./ -B rv-virt -P /private/tmp/run-job-macos/nuttx -L /private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu -R qemu -C --json=/private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/pytest.json
cd tools/ci/testrun/script
python3 -m venv .venv
source .venv/bin/activate
pip3 install pytest pexpect serial

cd /private/tmp/run-job-macos/nuttx/tools/ci/testrun/script
python3 -m pytest -m 'qemu or rv_virt' ./ -B rv-virt -P /private/tmp/run-job-macos/nuttx -L /private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu -R qemu -C
exit

python3 \
  -m pytest \
  -m 'qemu or rv_virt' ./ \
  -B rv-virt \
  -P /private/tmp/run-job-macos/nuttx \
  -L /private/tmp/run-job-macos/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu \
  -R qemu \
  -C
exit

python3 \
  -m pytest \
  -m 'qemu or rv_virt' ./ \
  -B rv-virt \
  -P $HOME/riscv/nuttx \
  -L $HOME/riscv/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu \
  -R qemu \
  -C \
  --json=$HOME/riscv/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/pytest.json
exit

python3 -m venv .venv
source .venv/bin/activate
pip3 install pytest
python3 \
  -m pytest \
  -m 'qemu or rv_virt' ./ \
  -B rv-virt \
  -P . \
  -L boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu \
  -R qemu \
  -C \
  --json=boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/pytest.json
exit
```
