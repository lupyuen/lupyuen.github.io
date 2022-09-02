# NuttX RTOS on PinePhone: UART Driver

📝 _9 Sep 2022_

![PinePhone Hacking with Pinebook Pro and BLÅHAJ](https://lupyuen.github.io/images/serial-title.jpg)

_PinePhone Hacking with Pinebook Pro and BLÅHAJ_

Last week we spoke about creating our own __Operating System__ for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)...

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

Our PinePhone OS will be awfully quiet if we don't implement __UART Input and Output__. (For the Serial Debug Console)

Today we'll learn about the __UART Controller__ for the Allwinner A64 SoC inside PinePhone...

And how we implemented PinePhone's __UART Driver__ [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) 

Let's dive into our __Porting Journal__ for NuttX on PinePhone...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

# UART With Polling

TODO

## Transmit UART

TODO

## Wait for UART

TODO

# UART With Interrupts

TODO

## Enable Interrupt

TODO

## Interrupt Handler 

TODO

## UART Transmit

TODO

## UART Receive

TODO

# Initialise UART

TODO

```text
Starting kernel ...

HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

nx_start: Entry
up_allocate_heap: heap_start=0x0x400c4000, heap_size=0x7f3c000

arm64_gic_initialize: TODO: Init GIC for PinePhone
arm64_gic_initialize: CONFIG_GICD_BASE=0x1c81000
arm64_gic_initialize: CONFIG_GICR_BASE=0x1c82000
arm64_gic_initialize: GIC Version is 2

up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 24.00MHz, cycle 24000
up_timer_initialize: _vector_table=0x400a7000
up_timer_initialize: Before writing: vbar_el1=0x40227000
up_timer_initialize: After writing: vbar_el1=0x400a7000

uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0

work_start_highpri: Starting high-priority kernel worker thread(s)
nx_start_application: Starting init thread
lib_cxx_initialize: _sinit: 0x400a7000 _einit: 0x400a7000 _stext: 0x40080000 _etext: 0x400a8000
nsh: sysinit: fopen failed: 2

nshn:x _msktfaarttf:s :C PcUo0m:m aBnedg innonti nfgo uInddle  L oNouptt
 Shell (NSH) NuttX-10.3.0-RC2
```
(Yeah the output is slightly garbled, the UART Driver needs fixing)

Now that we have UART Interrupts, __NuttX Shell__ works perfectly OK on PinePhone...

```text
nsh> uname -a
NuttX 10.3.0-RC2 fc909c6-dirty Sep  1 2022 17:05:44 arm64 qemu-a53

nsh> help
help usage:  help [-v] [<cmd>]

  .         cd        dmesg     help      mount     rmdir     true      xd        
  [         cp        echo      hexdump   mv        set       truncate  
  ?         cmp       exec      kill      printf    sleep     uname     
  basename  dirname   exit      ls        ps        source    umount    
  break     dd        false     mkdir     pwd       test      unset     
  cat       df        free      mkrd      rm        time      usleep    

Builtin Apps:
  getprime  hello     nsh       ostest    sh        

nsh> hello
task_spawn: name=hello entry=0x4009b1a0 file_actions=0x400c9580 attr=0x400c9588 argv=0x400c96d0
spawn_execattrs: Setting policy=2 priority=100 for pid=3
Hello, World!!

nsh> ls /dev
/dev:
 console
 null
 ram0
 ram2
 ttyS0
 zero
```

[__Watch the Demo on YouTube__](https://youtube.com/shorts/WmRzfCiWV6o?feature=share)

# What's Next

TODO

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/serial.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/serial.md)
