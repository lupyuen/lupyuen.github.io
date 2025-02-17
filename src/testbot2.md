# QEMU Test Bot for Pull Requests: Beware of Semihosting Breakout (Apache NuttX RTOS)

📝 _16 Mar 2025_

![TODO](https://lupyuen.org/images/testbot2-title.jpg)

TODO

# QEMU Arm64

https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-arm64.sh

https://github.com/lupyuen/nuttx-build-farm/blob/main/arm64.exp

```text
## Boot NuttX on Arm64 QEMU:
## Single Core with virtio network, block, rng, serial driver (GICv3)
## https://nuttx.apache.org/docs/latest/platforms/arm64/qemu/boards/qemu-armv8a/index.html
spawn qemu-system-aarch64 \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=3 \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -global virtio-mmio.force-legacy=false \
  -device virtio-serial-device,bus=virtio-mmio-bus.0 \
  -chardev socket,telnet=on,host=127.0.0.1,port=3450,server=on,wait=off,id=foo \
  -device virtconsole,chardev=foo \
  -device virtio-rng-device,bus=virtio-mmio-bus.1 \
  -netdev user,id=u1,hostfwd=tcp:127.0.0.1:10023-10.0.2.15:23,hostfwd=tcp:127.0.0.1:15001-10.0.2.15:5001 \
  -device virtio-net-device,netdev=u1,bus=virtio-mmio-bus.2 \
  -drive file=./mydisk-1gb.img,if=none,format=raw,id=hd \
  -device virtio-blk-device,bus=virtio-mmio-bus.3,drive=hd \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx
```

# LLM Says Meh

Test with LLM 
Here is a Pull Request for Apache NuttX RTOS that I will check out to my computer and test on QEMU RISC-V 64-bit Kernel Mode. Is it safe to build and test this Pull Request on my computer?

# TODO

What about PinePhone

What about ESP32

Kind folks at Espressif could help to modify the scripts to test 

# What's Next

Special Thanks to __Mr Gregory Nutt__ for your guidance and kindness. I'm also grateful to [__My Sponsors__](https://lupyuen.org/articles/sponsor), for supporting my writing. 

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/testbot2.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/testbot2.md)
