# Failing a Continuous Integration Test for Apache NuttX RTOS (QEMU RISC-V)

📝 _30 Dec 2024_

![TODO](https://lupyuen.github.io/images/ci7-title.jpg)

TODO

# TODO

TODO: Run risc-v-05

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
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/c59a642a3f3c5934ec53d5d72dd6e01d)

TODO: Run QEMU

```bash
sudo docker exec \
  -it \
  nuttx \
  /bin/bash
cd
ps aux | more
cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*
cd /root/nuttx
ls -l
[In the CI Test Session: Press Ctrl-C a few times to stop it]
qemu-system-riscv32 -M virt -bios ./nuttx -nographic -drive index=0,id=userdata,if=none,format=raw,file=./fatfs.img -device virtio-blk-device,bus=virtio-mmio-bus.0,drive=userdata
ps
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/399d2ba7d964ba88cdbeb97f64778a0e)

TODO: Build citest ourselves and run QEMU

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
cd nuttx
tools/configure.sh rv-virt:citest
make -j
ls -l
qemu-system-riscv32 -M virt -bios ./nuttx -nographic
uname -a
ps
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4ec0df33c2b4b569c010fade5f471940)

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
