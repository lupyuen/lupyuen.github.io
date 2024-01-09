# Apache NuttX RTOS in a Web Browser? Adventures with TinyEMU and VirtIO

📝 _15 Jan 2024_

![Apache NuttX RTOS in a Web Browser... With TinyEMU and VirtIO](https://lupyuen.github.io/images/tinyemu-title.png) 

TODO

[__Demo of NuttX on TinyEMU__](https://lupyuen.github.io/nuttx-tinyemu/)

[__Apache NuttX RTOS__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358) (Real-Time Operating System) is a tiny operating system for 64-bit RISC-V Machines and many other platforms. (Arm, x64, ESP32, ...)

[__TinyEMU__](https://github.com/fernandotcl/TinyEMU) is a barebones RISC-V Emulator that runs in a [__Web Browser__](https://www.barebox.org/jsbarebox/?graphic=1). (Thanks to WebAssembly)

Can we boot NuttX in a Web Browser, with a little help from TinyEMU? Let's find out!

_Why are we doing this?_

We might run NuttX in a Web Browser and emulate the [__Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) RISC-V SBC. Which is great for testing NuttX Apps like [__Nim Blinky LED__](https://lupyuen.github.io/articles/nim)! Or even LVGL Apps with VirtIO Framebuffer?

Also Imagine: A __NuttX Dashboard__ that lights up in __Real-Time__, as the various NuttX Modules are activated... This is all possible when NuttX runs in a Web Browser!

(Sorry QEMU Emulator is a bit too complex to customise)

# Install TinyEMU

_How to run TinyEMU?_

We begin by installing [__TinyEMU RISC-V Emulator__](https://github.com/fernandotcl/TinyEMU) at the Command Line...

```bash
## Install TinyEMU on macOS
## https://github.com/fernandotcl/homebrew-fernandotcl
## https://github.com/lupyuen/TinyEMU/blob/master/.github/workflows/ci.yml#L20-L29
brew tap fernandotcl/homebrew-fernandotcl
brew install --HEAD fernandotcl/fernandotcl/tinyemu
temu https://bellard.org/jslinux/buildroot-riscv64.cfg

## Install TinyEMU on Ubuntu
## https://github.com/lupyuen/TinyEMU/blob/master/.github/workflows/ci.yml#L6-L13
sudo apt install libcurl4-openssl-dev libssl-dev zlib1g-dev libsdl2-dev
git clone https://github.com/fernandotcl/TinyEMU
cd TinyEMU
make

## Check TinyEMU. Should show...
## temu version 2019-02-10, Copyright (c) 2016-2018 Fabrice Bellard
temu   
```

[(See the __Build Script__)](https://github.com/lupyuen/TinyEMU/blob/master/.github/workflows/ci.yml)

_What about TinyEMU for the Web Browser?_

No Worries! Everything that runs in the __Command Line__ TinyEMU... Will also run in the __Web Browser__ TinyEMU!

# RISC-V Addresses for TinyEMU

_How will TinyEMU boot our Operating System?_

TinyEMU is hardcoded to run at these __RISC-V Addresses__: [riscv_machine.c](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L66-L82)

```c
#define LOW_RAM_SIZE           0x00010000  // 64KB
#define RAM_BASE_ADDR          0x80000000
#define CLINT_BASE_ADDR        0x02000000
#define CLINT_SIZE             0x000c0000

#define DEFAULT_HTIF_BASE_ADDR 0x40008000
#define VIRTIO_BASE_ADDR       0x40010000
#define VIRTIO_SIZE            0x1000
#define VIRTIO_IRQ             1

#define PLIC_BASE_ADDR         0x40100000
#define PLIC_SIZE              0x00400000
#define FRAMEBUFFER_BASE_ADDR  0x41000000
```

Thus TinyEMU shall boot our NuttX Kernel at __RAM_BASE_ADDR: `0x8000_0000`__.

[(Yep TinyEMU has a __Graphics Framebuffer__)](https://www.barebox.org/jsbarebox/?graphic=1)

_How to set this Boot Address in NuttX?_

Actually we don't! __NuttX for QEMU Emulator__ (64-bit RISC-V) is already configured to boot at __`0x8000_0000`__: [ld.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/scripts/ld.script#L21-L27)

```text
/* NuttX boots at 0x80000000 */
SECTIONS {
  . = 0x80000000;
  .text : { _stext = . ;
```

So we're all ready to boot NuttX QEMU on TinyEMU!

# Boot NuttX in TinyEMU

_How to start the TinyEMU Emulator?_

We create a TinyEMU [__Configuration File: `nuttx.cfg`__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/root-riscv64.cfg)

```json
{
  version: 1,
  machine: "riscv64",
  memory_size: 256,
  bios: "nuttx.bin",
}
```

This will start the __64-bit RISC-V Emulator__ and boot it with our [__NuttX Kernel: `nuttx.bin`__](TODO)

[(Booting Linux? __It's complicated__)](https://github.com/lupyuen/nuttx-tinyemu#tinyemu-config)

_How do we get the NuttX Kernel?_

TODO: Download __`nuttx.bin`__ from

TODO: Or build it ourselves

_That's all we need?_

Yep! Just go ahead and boot __NuttX in TinyEMU__...

```bash
$ temu nuttx.cfg
```

_Huh? But we're booting NuttX QEMU on TinyEMU!_

Exactly... __Nothing will appear__ in TinyEMU!

First we need to understand the HTIF Console for TinyEMU...

TODO: Pic of HTIF Console

# Print to HTIF Console

_How do we print something to the TinyEMU Console?_

TinyEMU supports [__Berkeley Host-Target Interface (HTIF)__](https://docs.cartesi.io/machine/target/architecture/#htif) for Console Output.

HTIF comes from the olden days of the [__RISC-V Spike Emulator__](https://github.com/riscv-software-src/riscv-isa-sim/issues/364#issuecomment-607657754)...

> "HTIF is a tether between a simulation host and target, not something that's supposed to resemble a real hardware device. It's not a RISC-V standard; it's a UC Berkeley standard"

_But how does it work?_

Use the Source, Luke! TinyEMU handles __HTIF Commands__ like so: [riscv_machine.c](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L129-L153)

```c
// Handle a HTIF Command in TinyEMU:
// `tohost` contains the HTIF Command
static void htif_handle_cmd(RISCVMachine *s) {

  // Bits 56 to 63 indicate the `device`
  // Bits 48 to 55 indicate the `command`
  uint32_t device = s->htif_tohost >> 56;
  uint32_t cmd    = (s->htif_tohost >> 48) & 0xff;

  // If `tohost` is 1: Quit the Emulator
  if (s->htif_tohost == 1) {
    printf("\nPower off.\n");
    exit(0);

  // If `device` and `command` are 1:
  // Print `buf` (Bits 0 to 7) to Console Output
  } else if (device == 1 && cmd == 1) {
    uint8_t buf[1];
    buf[0] = s->htif_tohost & 0xff;
    s->common.console->write_data(s->common.console->opaque, buf, 1);
```

So to print "__`1`__" (ASCII `0x31`) to the HTIF Console, we set...

- __`device`__ <br> = (htif_tohost >> 56) <br> = __`1`__

- __`cmd`__ <br> = (htif_tohost >> 48) <br> = __`1`__

- __`buf`__ <br> = (htif_tohost & 0xff) <br> = __`0x31`__

Which means that we write this value to __htif_tohost__...

- (`1` << 56) | (`1` << 48) | `0x31` <br> = __`0x0101_0000_0000_0031`__

_Where is htif_tohost?_

__htif_tohost__ is at [__DEFAULT_HTIF_BASE_ADDR: `0x4000_8000`__](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L66-L82)

(According to [__riscv_machine_init__](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L913-L927) and [__htif_write__](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L154-L178))

Thus we __print to HTIF Console__ like this...

```c
// Print `1` to HTIF Console
*(volatile uint64_t *) 0x40008000 // HTIF Base Address
  = 0x0101000000000031ul;         // device=1, cmd=1, buf=0x31
```

Let's test this in our NuttX Boot Code...

TODO: 123 Screenshot

# Print in RISC-V Assembly

_We're checking if NuttX is alive on TinyEMU..._

_How do we print something in the NuttX Boot Code?_

This will be a little delicate: Our NuttX Boot Code is in [__RISC-V Assembly__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/arch/risc-v/src/qemu-rv/qemu_rv_head.S)!

(Beause it's the first thing that runs when NuttX boots)

From the previous section, we print "__`123`__" to TinyEMU's HTIF Console like so...

```c
// Print `1` to HTIF Console
*(volatile uint64_t *) 0x40008000 // HTIF Base Address
  = 0x0101000000000031ul;         // device=1, cmd=1, buf=0x31

// Do the same for `2` and `3`
*(volatile uint64_t *) 0x40008000 = 0x0101000000000032ul;
*(volatile uint64_t *) 0x40008000 = 0x0101000000000033ul;
```

We flip it (and reverse it) into __RISC-V Assembly__...

```text
/* Print `123` to HTIF Console           */
/* Load HTIF Base Address to Register t0 */
li  t0, 0x40008000

/* Load to Register t1 the HTIF Command to print `1` */
li  t1, 0x0101000000000031
/* Store 64-bit double-word from Register t1 to HTIF Base Address, Offset 0 */
sd  t1, 0(t0)

/* Load to Register t1 the HTIF Command to print `2` */
li  t1, 0x0101000000000032
/* Store 64-bit double-word from Register t1 to HTIF Base Address, Offset 0 */
sd  t1, 0(t0)

/* Load to Register t1 the HTIF Command to print `3` */
li  t1, 0x0101000000000033
/* Store 64-bit double-word from Register t1 to HTIF Base Address, Offset 0 */
sd  t1, 0(t0)
```

[(__`li`__ loads a Value into a Register)](https://lupyuen.github.io/articles/riscv#other-instructions)

[(__`sd`__ stores a 64-bit Double-Word from a Register into an Address Offset)](https://five-embeddev.com/quickref/instructions.html#-rv64--load-and-store-instructions)

Then we work it into our __NuttX Boot Code__: [qemu_rv_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L43-L61)

_Does it work?_

NuttX prints something to the HTIF Console yay! Now we know that NuttX Boot Code is actually alive and running on TinyEMU...

```text
$ temu nuttx.cfg
123
```

To see more goodies, we fix the NuttX UART Driver...

TODO: UART screenshot

# Fix the NuttX UART Driver for TinyEMU

_NuttX on TinyEMU has been awfully quiet..._

_How to fix the UART Driver so that NuttX can print things?_

NuttX is still running on the __QEMU UART Driver__. (16550 UART)

Let's make a quick patch so that we will see something in TinyEMU's __HTIF Console__: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/serial/uart_16550.c#L1701-L1720)

```c
// Write one character to the UART Driver
static void u16550_putc(FAR struct u16550_s *priv, int ch) {

  // Hardcode the HTIF Base Address and print...
  *(volatile uint64_t *) 0x40008000
    // device=1, cmd=1, buf=ch
    = 0x0101000000000000ul | ch;
}
```

We skip the reading and writing of other __UART Registers__ (because we'll patch them later): [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/serial/uart_16550.c#L604-L635)

```c
// Read UART Register
static inline uart_datawidth_t u16550_serialin(FAR struct u16550_s *priv, int offset) {
  return 0;
  // Commented out the rest
}

// Write UART Register
static inline void u16550_serialout(FAR struct u16550_s *priv, int offset, uart_datawidth_t value) {
  // Commented out the rest
}
```

And we won't wait for __UART Ready__, since we're not accessing the Line Control Register: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/serial/uart_16550.c#L635-L673)

```c
// Wait until UART is not busy
static int u16550_wait(FAR struct u16550_s *priv) {
  // Nopez! No waiting for now
  return OK;
}
```

_What happens when we run this?_

Now we see NuttX booting OK on TinyEMU yay! (Later we'll fix the NuttX Shell)

```text
+ temu nuttx.cfg
123ABC
nx_start: Entry
mm_initialize: Heap: name=Umem, start=0x80035700 size=33335552
mm_addregion: [Umem] Region 1: base=0x800359a8 size=33334864
builtin_initialize: Registering Builtin Loader
elf_initialize: Registering ELF

uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
nx_start_application: Starting init thread
task_spawn: name=nsh_main entry=0x80006fde file_actions=0 attr=0x80035670 argv=0x80035668
nx_start: CPU0: Beginning Idle Loop
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/8805f8f21dfae237bc06dfbda210628b)

Let's boot NuttX in the Web Browser...

TODO: NuttX in Web Browser

# Boot NuttX in the Web Browser

TODO

_Will NuttX boot in the Web Browser?_

Yep! WebAssembly Demo is here: [Demo of NuttX on TinyEMU](https://lupyuen.github.io/nuttx-tinyemu/)

WebAssembly Files are located here: [nuttx-tinyemu/docs](https://github.com/lupyuen/nuttx-tinyemu/tree/main/docs)

We copied the TinyEMU Config and NuttX Kernel to the Web Server...

```bash
## Copy to Web Server: NuttX Config, Kernel, Disassembly (for troubleshooting)
cp nuttx.cfg ../nuttx-tinyemu/docs/root-riscv64.cfg
cp nuttx.bin ../nuttx-tinyemu/docs/
cp nuttx.S ../nuttx-tinyemu/docs/
```

The other files were provided by [TinyEMU](https://bellard.org/tinyemu/)...

- [jslinux-2019-12-21.tar.gz](https://bellard.org/tinyemu/jslinux-2019-12-21.tar.gz): Precompiled JSLinux demo

_How to test this locally?_

To test on our computer, we need to install a Local Web Server (because our Web Browser won't load WebAssembly Files from the File System)...

```bash
## Based on https://github.com/TheWaWaR/simple-http-server
$ cargo install simple-http-server
$ git clone https://github.com/lupyuen/nuttx-tinyemu
$ simple-http-server nuttx-tinyemu/docs
```

Then browse to...

```text
http://0.0.0.0:8000/index.html
```

_But there's no Console Input?_

To do Console Input, we need to implement VirtIO Console in our NuttX UART Driver...

TODO: Pic of VirtIO Console, OpenAMP

# VirtIO Console in TinyEMU

TODO

_How will we implement Console Input / Output in NuttX TinyEMU?_

TinyEMU supports VirtIO for proper Console Input and Output...

- [TinyEMU support for VirtIO](https://bellard.org/tinyemu/readme.txt)

- [Virtio - OSDev Wiki](https://wiki.osdev.org/Virtio)

- [Virtual I/O Device (VIRTIO) Spec, Version 1.2](https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html)

- [About VirtIO Console](https://projectacrn.github.io/latest/developer-guides/hld/virtio-console.html)

And NuttX supports VirtIO, based on OpenAMP...

- [Running NuttX with VirtIO on QEMU](https://www.youtube.com/watch?v=_8CpLNEWxfo)

- [NuttX VirtIO Framework and Future Works](https://www.youtube.com/watch?v=CYMkAv-WjQg)

- [Intro to OpenAMP](https://www.openampproject.org/docs/whitepapers/Introduction_to_OpenAMPlib_v1.1a.pdf)

- [knetnsh64: NuttX for QEMU RISC-V with VirtIO](https://github.com/apache/nuttx/blob/master/boards/risc-v/qemu-rv/rv-virt/configs/knetnsh64/defconfig#L52)

But let's create a simple VirtIO Console Driver for NuttX with OpenAMP...

- Create Queue: Call OpenAMP [virtqueue_create](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L49)

  (See [virtio_mmio_create_virtqueue](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-mmio.c#L349-L414) or [virtio_create_virtqueues](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtio.c#L96-L142))

- Send Data: Call OpenAMP [virtqueue_add_buffer](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L83C1-L138)

  (See [virtio_serial_dmasend](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L310-L345))

- Start Processing: Call OpenAMP [virtqueue_kick](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L321-L336)

  (See [virtio_serial_dmasend](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L310-L345))

This will help us understand the inner workings of VirtIO and OpenAMP! But first we enable VirtIO and OpenAMP in NuttX...

# Enable VirtIO and OpenAMP in NuttX

TODO

_How do we call VirtIO and OpenAMP?_

To enable VirtIO and OpenAMP in NuttX:

```text
make menuconfig
## Device Drivers
##   Enable "Simple AddrEnv"
##   Enable "Virtio Device Support"

## Device Drivers > Virtio Device Support
##   Enable "Virtio MMIO Device Support"

## Build Setup > Debug Options >
##   Enable "Virtio Debug Features > Error, Warnings, Info"
```

_Why "Simple AddrEnv"?_

`up_addrenv_va_to_pa` is defined in [drivers/misc/addrenv.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/misc/addrenv.c#L89-L112). So we need `CONFIG_DEV_SIMPLE_ADDRENV` (Simple AddrEnv)

Otherwise we see this...

```text
riscv64-unknown-elf-ld: nuttx/staging/libopenamp.a(io.o): in function `metal_io_phys_to_offset_':
nuttx/openamp/libmetal/lib/system/nuttx/io.c:105: undefined reference to `up_addrenv_pa_to_va'
riscv64-unknown-elf-ld: nuttx/staging/libopenamp.a(io.o): in function `metal_io_offset_to_phys_':
nuttx/openamp/libmetal/lib/system/nuttx/io.c:99: undefined reference to `up_addrenv_va_to_pa'
```

Now we configure NuttX VirtIO...

# Configure NuttX VirtIO for TinyEMU

TODO

_How to make NuttX VirtIO talk to TinyEMU?_

Previously we saw the TinyEMU config: [riscv_machine.c](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L66-L82)

```c
#define VIRTIO_BASE_ADDR 0x40010000
#define VIRTIO_SIZE      0x1000
#define VIRTIO_IRQ       1
```

Now we set the VirtIO Parameters for TinyEMU in NuttX: [qemu_rv_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L41-L49)

```c
#define QEMU_VIRTIO_MMIO_BASE    0x40010000 // VIRTIO_BASE_ADDR. Previously: 0x10001000
#define QEMU_VIRTIO_MMIO_REGSIZE 0x1000     // VIRTIO_SIZE
#ifdef CONFIG_ARCH_USE_S_MODE
#  define QEMU_VIRTIO_MMIO_IRQ   26 // TODO: Should this be 1? (VIRTIO_IRQ)
#else
#  define QEMU_VIRTIO_MMIO_IRQ   28 // TODO: Should this be 1? (VIRTIO_IRQ)
#endif
#define QEMU_VIRTIO_MMIO_NUM     1  // Number of VirtIO Devices. Previously: 8
```

With these settings, VirtIO and OpenAMP will start OK on NuttX yay!

```text
virtio_mmio_init_device: VIRTIO version: 2 device: 3 vendor: ffff
mm_malloc: Allocated 0x80046a90, size 48
test_virtio: 
mm_malloc: Allocated 0x80046ac0, size 848
nx_start: CPU0: Beginning Idle Loop
```

Which means NuttX VirtIO + OpenAMP has successfully validated the Magic Number from TinyEMU. (Otherwise NuttX will halt)

_How does it work?_

At NuttX Startup: [board_app_initialize](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L77-L123) calls...

- [qemu_virtio_register_mmio_devices](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L54-L73) (to register all VirtIO MMIO Devices) which calls...

- [virtio_register_mmio_device](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/virtio/virtio-mmio.c#L809-L932) 
(to register a VirtIO MMIO Device, explained below)

Let's create a VirtIO Queue for the VirtIO Console and send some data...

![Apache NuttX RTOS in the Web Browser: TinyEMU with VirtIO](https://lupyuen.github.io/images/tinyemu-title.png)

# Test TinyEMU VirtIO Console with NuttX

TODO

_NuttX has started VirtIO and OpenAMP and they talk nicely to TinyEMU. What next?_

We dig around NuttX and we see NuttX creating a VirtIO Queue for VirtIO Console: [virtio_serial_init](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L445-L511) calls...

- OpenAMP [virtio_create_virtqueues](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtio.c#L96-L142) (create data queues, explained below)

Also we see NuttX sending data to VirtIO Console: [virtio_serial_dmasend](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L310-L345) calls...

- OpenAMP [virtqueue_add_buffer](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L83C1-L138) (send data to queue) and...

  OpenAMP [virtqueue_kick](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L321-L336) (start queue processing, explained below)

Let's do all these in our NuttX Test Code: [virtio-mmio.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/virtio/virtio-mmio.c#L870-L925)

```c
  // Testing: Init VirtIO Device
  // Based on virtio_serial_init
  // https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L445-L511

  struct virtio_device *vdev = &vmdev->vdev;
  DEBUGASSERT(vdev != NULL);

  virtio_set_status(vdev, VIRTIO_CONFIG_STATUS_DRIVER);
  virtio_set_features(vdev, 0);
  virtio_set_status(vdev, VIRTIO_CONFIG_FEATURES_OK);

  #define VIRTIO_SERIAL_RX           0
  #define VIRTIO_SERIAL_TX           1
  #define VIRTIO_SERIAL_NUM          2
  const char *vqnames[VIRTIO_SERIAL_NUM];
  vqnames[VIRTIO_SERIAL_RX]   = "virtio_serial_rx";
  vqnames[VIRTIO_SERIAL_TX]   = "virtio_serial_tx";

  vq_callback callbacks[VIRTIO_SERIAL_NUM];
  callbacks[VIRTIO_SERIAL_RX] = NULL; // TODO: virtio_serial_rxready;
  callbacks[VIRTIO_SERIAL_TX] = NULL; // TODO: virtio_serial_txdone;
  ret = virtio_create_virtqueues(vdev, 0, VIRTIO_SERIAL_NUM, vqnames,
                                 callbacks);
  DEBUGASSERT(ret >= 0);
  virtio_set_status(vdev, VIRTIO_CONFIG_STATUS_DRIVER_OK);

  // Testing: Send data to VirtIO Device
  // Based on virtio_serial_dmasend
  // https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L310-L345

  DEBUGASSERT(vdev->vrings_info != NULL);
  struct virtqueue *vq = vdev->vrings_info[VIRTIO_SERIAL_TX].vq;
  DEBUGASSERT(vq != NULL);

  /* Set the virtqueue buffer */
  static char *HELLO_MSG = "Hello VirtIO from NuttX!\r\n";
  struct virtqueue_buf vb[2];
  vb[0].buf = HELLO_MSG;
  vb[0].len = strlen(HELLO_MSG);
  int num = 1;

  /* Get the total send length */
  uintptr_t len = strlen(HELLO_MSG);

  // TODO: What's this?
  // if (xfer->nlength != 0)
  //   {
  //     vb[1].buf = xfer->nbuffer;
  //     vb[1].len = xfer->nlength;
  //     num = 2;
  //   }

  /* Add buffer to TX virtiqueue and notify the VirtIO Host */
  virtqueue_add_buffer(vq, vb, num, 0, (FAR void *)len);
  virtqueue_kick(vq);  
  // End of Testing
```

_Does it work?_

Yep NuttX prints correctly to TinyEMU's VirtIO Console yay!

[__Demo of NuttX on TinyEMU: lupyuen.github.io/nuttx-tinyemu__](https://lupyuen.github.io/nuttx-tinyemu/)

```text
+ temu nuttx.cfg
123ABCnx_start: Entry
builtin_initialize: Registering Builtin Loader
elf_initialize: Registering ELF
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
nx_start_application: Starting init thread
task_spawn: name=nsh_main entry=0x8000756e file_actions=0 attr=0x80043e80 argv=0x80043e78
virtio_mmio_init_device: VIRTIO version: 2 device: 3 vendor: ffff
Hello VirtIO from NuttX!
nx_start: CPU0: Beginning Idle Loop
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/8805f8f21dfae237bc06dfbda210628b)

Up Next: Implement Console Input / Output with the NuttX Serial Driver for VirtIO

But for now: Let's look inside our VirtIO Guest (NuttX) and VirtIO Host (TinyEMU)...

![Apache NuttX RTOS in the Web Browser: TinyEMU with VirtIO](https://lupyuen.github.io/images/tinyemu-title.png)

# Inside the VirtIO Driver for NuttX

TODO

_How does VirtIO Guest work in NuttX?_

NuttX VirtIO Driver is based on OpenAMP with MMIO...

- [Running NuttX with VirtIO on QEMU](https://www.youtube.com/watch?v=_8CpLNEWxfo)

- [NuttX VirtIO Framework and Future Works](https://www.youtube.com/watch?v=CYMkAv-WjQg)

At NuttX Startup: [board_app_initialize](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L77-L123) calls...

- [qemu_virtio_register_mmio_devices](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L54-L73) (to register all VirtIO MMIO Devices) which calls...

- [virtio_register_mmio_device](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/virtio/virtio-mmio.c#L809-L932) 
(to register a VirtIO MMIO Device) which calls...

- [virtio_mmio_init_device](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-mmio.c#L740-L805) which passes...

- [g_virtio_mmio_dispatch](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-mmio.c#L234-L254) which contains...

- [virtio_mmio_create_virtqueues](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-mmio.c#L419) which calls...

- [virtio_mmio_create_virtqueue](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-mmio.c#L349-L414) which calls...

- [virtqueue_create](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L49) (OpenAMP)

To create a VirtIO Queue for VirtIO Console: [virtio_serial_probe](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L530) calls...

- [virtio_serial_init](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L445-L511) which calls...

- [virtio_create_virtqueues](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtio.c#L96-L142) (OpenAMP)

To send data to VirtIO Console: [virtio_serial_send](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L245) calls...

- [virtio_serial_dmatxavail](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L345-L357) which calls...

- [uart_xmitchars_dma](https://github.com/apache/nuttx/blob/master/drivers/serial/serial_dma.c#L86-L125) which calls...

- [virtio_serial_dmasend](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L310-L345) which calls...

- [virtqueue_add_buffer](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L83C1-L138) (OpenAMP) and...

  [virtqueue_kick](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L321-L336) (OpenAMP)

# Inside the VirtIO Host for TinyEMU

TODO

_How does VirtIO Host work in TinyEMU?_

Let's look inside the implementation of VirtIO in TinyEMU...

## TinyEMU VirtIO

TODO

TinyEMU supports these VirtIO Devices:

- Console Device

- [Block Device](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L979-L1133)

- [Network Device](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L1133-L1259)

- [Input Device](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L1361-L1645)

- [9P Filesystem Device](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L1645-L2649)

The Device IDs are: [virtio_init](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L219-L297)

```c
switch(device_id) {
case 1: /* net */ ...
case 2: /* block */ ...
case 3: /* console */ ...
case 9: /* Network Device */ ...
case 18: /* Input Device */ ...
```

TinyEMU supports VirtIO over MMIO and PCI:

- [MMIO addresses](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L37)

- [PCI registers](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L66)

TinyEMU Guests (like NuttX) are required to check the [VIRTIO_MMIO_MAGIC_VALUE](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L617) that's returned by the TinyEMU Host.

## TinyEMU VirtIO Console

TODO

From above: VirtIO Console is Device ID 3. Here's how it works...

At TinyEMU Startup: [riscv_machine_init](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L952) calls...

- [virtio_console_init](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L1347-L1361) which calls...

- [virtio_init](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L219-L297) with Device ID 3

To print to VirtIO Console: [virt_machine_run (js)](https://github.com/fernandotcl/TinyEMU/blob/master/jsemu.c#L304-L348) and [virt_machine_run (temu)](https://github.com/fernandotcl/TinyEMU/blob/master/temu.c#L545-L610) call...

- [virtio_console_write_data](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L1317-L1337) which calls...

- [memcpy_to_queue](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L451-L459) which calls...

- [memcpy_to_from_queue](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L380)

Which will access...

- [QueueState](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L97-L107): For desc_addr, avail_addr, used_addr

- [VIRTIODesc](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L111-L118): For [VirtualQueue::Buffers[QueueSize]](https://wiki.osdev.org/Virtio#Virtual_Queue_Descriptor)

TinyEMU Console Device:

- [console device decl](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.h#L108)

- [console device impl](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L1261)

## TinyEMU VirtIO MMIO Queue

TODO

TinyEMU Guest (like NuttX) is required to set the VirtIO Queue Desc / Avail / Used.

This is how TinyEMU accesses the VirtIO MMIO Queue: [virtio.c](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L645)

```c
case VIRTIO_MMIO_QUEUE_SEL:
    val = s->queue_sel;
    break;
case VIRTIO_MMIO_QUEUE_NUM_MAX:
    val = MAX_QUEUE_NUM;
    break;
case VIRTIO_MMIO_QUEUE_NUM:
    val = s->queue[s->queue_sel].num;
    break;
case VIRTIO_MMIO_QUEUE_DESC_LOW:
    val = s->queue[s->queue_sel].desc_addr;
    break;
case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
    val = s->queue[s->queue_sel].avail_addr;
    break;
case VIRTIO_MMIO_QUEUE_USED_LOW:
    val = s->queue[s->queue_sel].used_addr;
    break;
#if VIRTIO_ADDR_BITS == 64
case VIRTIO_MMIO_QUEUE_DESC_HIGH:
    val = s->queue[s->queue_sel].desc_addr >> 32;
    break;
case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
    val = s->queue[s->queue_sel].avail_addr >> 32;
    break;
case VIRTIO_MMIO_QUEUE_USED_HIGH:
    val = s->queue[s->queue_sel].used_addr >> 32;
    break;
#endif
```

To Select and Notify the Queue:

- [VIRTIO_MMIO_QUEUE_SEL](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L741)

- [VIRTIO_MMIO_QUEUE_NOTIFY](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L781)

# NuttX in Kernel Mode

TODO

_Right now we're running NuttX in Flat Mode..._

_Can NuttX run in Kernel Mode on TinyEMU?_

NuttX Kernel Mode requires [RISC-V Semihosting](https://lupyuen.github.io/articles/semihost#semihosting-on-nuttx-qemu) to access the NuttX Apps Filesystem. Which is supported by QEMU but not TinyEMU.

But we can [Append the Initial RAM Disk](https://lupyuen.github.io/articles/app#initial-ram-disk) to the NuttX Kernel. So yes it's possible to run NuttX in Kernel Mode with TinyEMU, with some additional [Mounting Code](https://lupyuen.github.io/articles/app#mount-the-initial-ram-disk).

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tinyemu.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tinyemu.md)

# Appendix: Build NuttX for TinyEMU

TODO

In this article, we compiled a Work-In-Progress Version of __Apache NuttX RTOS for QEMU RISC-V (64-bit)__ that has Minor Fixes for Nim...

TODO

TODO: Then we download and build NuttX for __QEMU RISC-V (64-bit)__...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch nim \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Configure NuttX for QEMU RISC-V (64-bit)
cd nuttx
tools/configure.sh rv-virt:nsh64

## Build NuttX
make

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

TODO: [(See the __Build Script__)](https://github.com/lupyuen/nuttx-nim/releases/tag/qemu-1)

TODO: [(See the __Build Log__)](https://gist.github.com/lupyuen/09e653cbd227b9cdff7cf3cb0a5e1ffa)

TODO: [(See the __Build Outputs__)](https://github.com/lupyuen/nuttx-nim/releases/tag/qemu-1)

TODO: This produces the NuttX ELF Image __`nuttx`__ that we may boot on QEMU RISC-V Emulator...

```bash
## Start the QEMU RISC-V Emulator (64-bit) with NuttX RTOS
qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic
```

TODO: To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

So we build NuttX for QEMU RISC-V (64-bit, Flat Mode)...

```bash
## Download WIP NuttX
git clone --branch tinyemu https://github.com/lupyuen2/wip-pinephone-nuttx nuttx
git clone --branch tinyemu https://github.com/lupyuen2/wip-pinephone-nuttx-apps apps

## Configure NuttX for QEMU RISC-V (64-bit, Flat Mode)
cd nuttx
tools/configure.sh rv-virt:nsh64
make menuconfig
## Device Drivers
##   Enable "Simple AddrEnv"
##   Enable "Virtio Device Support"

## Device Drivers > Virtio Device Support
##   Enable "Virtio MMIO Device Support"

## Build Setup > Debug Options >
##   Enable Debug Features
##   Enable "Debug Assertions > Show Expression, Filename"
##   Enable "Binary Loader Debug Features > Errors, Warnings, Info"
##   Enable "File System Debug Features > Errors, Warnings, Info"
##   Enable "C Library Debug Features > Errors, Warnings, Info"
##   Enable "Memory Manager Debug Features > Errors, Warnings, Info"
##   Enable "Scheduler Debug Features > Errors, Warnings, Info"
##   Enable "Timer Debug Features > Errors, Warnings, Info"
##   Enable "IPC Debug Features > Errors, Warnings, Info"
##   Enable "Virtio Debug Features > Error, Warnings, Info"

## Application Configuration > Testing >
##   Enable "OS Test Example"

## RTOS Features > Tasks and Scheduling >
##   Set "Application Entry Point" to "ostest_main"
##   Set "Application Entry Name" to "ostest_main"
## Save and exit menuconfig

## Build NuttX
make

## Export the Binary Image to nuttx.bin
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1
```
