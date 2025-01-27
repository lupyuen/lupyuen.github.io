# Auto-Rewind for Daily Test (Apache NuttX RTOS)

📝 _26 Feb 2025_

![TODO](https://lupyuen.github.io/images/rewind-title.jpg)

If the __Daily Test__ fails for [__Apache NuttX RTOS__](TODO)... Can we __Auto-Rewind__ and discover the __Breaking Commit__? Let's find out!

1.  Every Day at 00:00 UTC: [__Ubuntu Cron__](TODO) shall trigger a __Daily Buld and Test__ of NuttX for __QEMU RISC-V__ _(knsh64 / 64-bit Kernel Build)_

1.  __If The Test Fails:__ Our Machine will [__Backtrack The Commits__](TODO), rebuilding and retesting each commit _(on QEMU Emulator)_

1.  When it discovers the __Breaking Commit__: Our Machine shall post a [__Mastodon Alert__](TODO), that includes the _(suspicious)_ __Pull Request__

1.  __Bonus:__ The Machine will draft a [__Polite Note__](TODO) for our NuttX Colleague to investigate the Pull Request, please

_Why are we doing this?_

__If NuttX Fails on QEMU RISC-V:__ High chance that NuttX will also fail on __RISC-V SBCs__ like Ox64 BL808 and Oz64 SG2000.

Thus it's important to Nip the Bud and Fix the Bug, before it hurts our RISC-V Devs. _(Be Kind, Rewind!)_

# TODO

```text
Sort by Log Timestamp

Add Log Timestamp
https://github.com/lupyuen/ingest-nuttx-builds/commit/055149d999c6727183b843feedce6d3086062a24

Sort: Timestamp + NuttX Hash
TODO: Add timestamp_log (from Snippet)

Parse OSTest correctly
https://github.com/lupyuen/ingest-nuttx-builds/commit/b4eb156075002bafa510230c2120f70e09f7cf12

. ../gitlab-token.sh && glab auth status && ./rewind-build.sh rv-virt:knsh64_test aa0aecbd80a2ce69ee33ced41b7677f8521acd43 a6b9e718460a56722205c2a84a9b07b94ca664aa

30 mins for 7 rewinds

build-test
If fail
Rewind-build
Use latest hashes

lookup prometheus
Compose Mastodon message 
Get pr, author 
Link to build history 
Earlier build is ok
Run log snippet 
Uname
Last few lines

TODO: daily cron
https://help.ubuntu.com/community/CronHowto

TODO: Get hashes from Prometheus 

https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-knsh64-2025-01-12
NuttX Source: https://github.com/apache/nuttx/tree/aa0aecbd80a2ce69ee33ced41b7677f8521acd43
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa

https://github.com/apache/nuttx/pull/15444#issuecomment-2585595498
Sorry @yf13: This PR is causing "Instruction page fault" for rv-virt:knsh64. Wonder if there's something I missed in my testing steps? Thanks!

https://gist.github.com/lupyuen/60d54514ce9a8589b56ed6207c356d95#file-special-qemu-riscv-knsh64-log-L1396
+ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
HEAD is now at 657247bda8 libc/modlib: preprocess gnu-elf.ld
NuttX Source: https://github.com/apache/nuttx/tree/657247bda89d60112d79bb9b8d223eca5f9641b5
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa
+ tools/configure.sh rv-virt:knsh64
+ make -j
+ make export
+ pushd ../apps
+ ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-12.8.0.tar.gz
+ make import
+ popd
+ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic
QEMU emulator version 9.2.0
OpenSBI v1.5.1
ABC
riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000018000001a, MTVAL: 000000018000001a
riscv_exception: Segmentation fault in PID 2: /system/bin/init
(Earlier Commit is OK)
```

# What's Next

TODO

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And [__My Sponsors__](https://lupyuen.org/articles/sponsor), for sticking with me all these years.

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/rewind.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/rewind.md)
