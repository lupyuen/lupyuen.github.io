# Apache NuttX RTOS in a Web Browser? Adventures with TinyEMU and VirtIO

📝 _15 Jan 2024_

![Apache NuttX RTOS in a Web Browser... With TinyEMU and VirtIO](https://lupyuen.github.io/images/tinyemu-title.png) 

[_(Live Demo of NuttX on TinyEMU)_](https://lupyuen.github.io/nuttx-tinyemu/)

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html) is a tiny operating system for [__64-bit RISC-V Machines__](https://lupyuen.github.io/articles/riscv) and many other platforms. (Arm, x64, ESP32, ...)

[__TinyEMU__](https://github.com/fernandotcl/TinyEMU) is a barebones RISC-V Emulator that runs in a [__Web Browser__](https://www.barebox.org/jsbarebox/?graphic=1). (Thanks to WebAssembly)

Can we boot __NuttX inside a Web Browser__, with a little help from TinyEMU? Let's find out!

In this article we...

TODO

_Why are we doing this?_

We might run NuttX in a Web Browser and emulate the [__Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) RISC-V SBC. Which is great for testing NuttX Apps like [__Nim Blinky LED__](https://lupyuen.github.io/articles/nim)! (LVGL Graphical Apps too)

Also Imagine: A __NuttX Dashboard__ that lights up in __Real-Time__, as the various NuttX Drivers are activated... This is all possible when NuttX runs in a Web Browser!

(Sorry QEMU Emulator is a bit too complex to customise)

![TinyEMU does Doom in a Web Browser](https://lupyuen.github.io/images/tinyemu-doom.png) 

> [_TinyEMU does Doom in Web Browser_](https://www.barebox.org/jsbarebox/?graphic=1)

# Install TinyEMU Emulator

_How to run TinyEMU?_

We begin by installing [__TinyEMU RISC-V Emulator__](https://github.com/fernandotcl/TinyEMU) at the Command Line...

```bash
## Install TinyEMU on macOS
## https://github.com/fernandotcl/homebrew-fernandotcl
## https://github.com/lupyuen/TinyEMU/blob/master/.github/workflows/ci.yml#L20-L29
brew tap fernandotcl/homebrew-fernandotcl
brew install --HEAD fernandotcl/fernandotcl/tinyemu

## Install TinyEMU on Ubuntu
## https://github.com/lupyuen/TinyEMU/blob/master/.github/workflows/ci.yml#L6-L13
sudo apt install libcurl4-openssl-dev libssl-dev zlib1g-dev libsdl2-dev
git clone https://github.com/fernandotcl/TinyEMU
cd TinyEMU
make
sudo make install

## Check TinyEMU. Should show:
## temu version 2019-02-10, Copyright (c) 2016-2018 Fabrice Bellard
temu

## Boot RISC-V Linux on TinyEMU (pic below)
temu https://bellard.org/jslinux/buildroot-riscv64.cfg
```

[(See the __Build Script__)](https://github.com/lupyuen/TinyEMU/blob/master/.github/workflows/ci.yml)

_What about TinyEMU for the Web Browser?_

No Worries! Everything that runs in __Command Line__ TinyEMU... Will also run in __Web Browser__ TinyEMU!

TODO: TinyEMU Linux

# RISC-V Addresses for TinyEMU

_How will TinyEMU boot our Operating System?_

TinyEMU is hardcoded to run at these __RISC-V Addresses__: [riscv_machine.c](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L66-L82)

```c
// RISC-V Addresses for TinyEMU Emulator
#define LOW_RAM_SIZE           0x00010000  // 64KB
#define RAM_BASE_ADDR          0x80000000
#define CLINT_BASE_ADDR        0x02000000
#define CLINT_SIZE             0x000c0000

// HTIF Console and Virtual I/O
#define DEFAULT_HTIF_BASE_ADDR 0x40008000
#define VIRTIO_BASE_ADDR       0x40010000
#define VIRTIO_SIZE            0x1000
#define VIRTIO_IRQ             1

// Interrupt Controller and Framebuffer
#define PLIC_BASE_ADDR         0x40100000
#define PLIC_SIZE              0x00400000
#define FRAMEBUFFER_BASE_ADDR  0x41000000
```

Thus TinyEMU will boot our NuttX Kernel at __`0x8000_0000`__. _(RAM_BASE_ADDR)_

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

[(Booting Linux? __It's more complicated__)](https://github.com/lupyuen/nuttx-tinyemu#tinyemu-config)

_NuttX Kernel comes from?_

TODO: Download __`nuttx.bin`__ from

TODO: Or build it ourselves

_That's all we need?_

Yep! Just go ahead and boot __NuttX in TinyEMU__...

```bash
$ temu nuttx.cfg
```

[(Copy __`nuttx.cfg`__ from here)](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/root-riscv64.cfg)

_Huh! We're booting NuttX QEMU on TinyEMU?_

Exactly... __Nothing will appear__ in TinyEMU!

To watch NuttX run, we need HTIF Console...

TODO: Pic of HTIF Console

# Print to HTIF Console

_How do we print something to the TinyEMU Console?_

TinyEMU supports [__Berkeley Host-Target Interface (HTIF)__](https://docs.cartesi.io/machine/target/architecture/#htif) for Console Output.

HTIF comes from the olden days of the [__RISC-V Spike Emulator__](https://github.com/riscv-software-src/riscv-isa-sim/issues/364#issuecomment-607657754)...

> "HTIF is a tether between a simulation host and target, not something that's supposed to resemble a real hardware device"

> "It's not a RISC-V standard; it's a UC Berkeley standard"

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

- __`device`__ <br> = (_htif_tohost_ >> `56`) <br> = __`1`__

- __`cmd`__ <br> = (_htif_tohost_ >> `48`) <br> = __`1`__

- __`buf`__ <br> = (_htif_tohost_ & `0xFF`) <br> = __`0x31`__

Which means that we write this value to __htif_tohost__...

- (`1` << `56`) | (`1` << `48`) | `0x31` <br> = __`0x0101_0000_0000_0031`__

_Where is htif_tohost?_

__htif_tohost__ is at [__`0x4000_8000`__](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L66-L82) _(DEFAULT_HTIF_BASE_ADDR)_

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

```bash
$ temu nuttx.cfg
123
```

[(Copy __`nuttx.cfg`__ from here)](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/root-riscv64.cfg)

To see more goodies, we fix the NuttX UART Driver...

TODO: UART screenshot

# UART Driver for TinyEMU

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

```bash
$ temu nuttx.cfg
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

![NuttX booting in a Web Browser](https://lupyuen.github.io/images/tinyemu-wasm.png) 

> [_NuttX booting in a Web Browser_](https://lupyuen.github.io/nuttx-tinyemu/)

# Boot NuttX in Web Browser

_Will NuttX boot in the Web Browser?_

Yep! (Pic above)

- WebAssembly Demo: [__NuttX on TinyEMU__](https://lupyuen.github.io/nuttx-tinyemu/)

- WebAssembly Files: [__nuttx-tinyemu/docs__](https://github.com/lupyuen/nuttx-tinyemu/tree/main/docs)

_So Cool! How did we make this?_

We copied the __TinyEMU Config__ and __NuttX Kernel__ to the Web Server...

```bash
## Copy to Web Server: NuttX Config, Kernel, Disassembly (for troubleshooting)
cp nuttx.cfg $HOME/nuttx-tinyemu/docs/root-riscv64.cfg
cp nuttx.bin $HOME/nuttx-tinyemu/docs/
cp nuttx.S   $HOME/nuttx-tinyemu/docs/
```

The other [__WebAssembly Files__](https://github.com/lupyuen/nuttx-tinyemu/tree/main/docs) were provided by [__TinyEMU__](https://bellard.org/tinyemu/)...

- Precompiled JSLinux Demo: [__jslinux-2019-12-21.tar.gz__](https://bellard.org/tinyemu/jslinux-2019-12-21.tar.gz)

Like we said: Everything that runs in __Command Line__ TinyEMU... Will also run in __Web Browser__ TinyEMU!

_How to test this locally?_

To test on our computer, we need to install a __Local Web Server__...

```bash
## Based on https://github.com/TheWaWaR/simple-http-server
$ cargo install simple-http-server
$ git clone https://github.com/lupyuen/nuttx-tinyemu
$ simple-http-server nuttx-tinyemu/docs
```

That's because our Web Browser won't load WebAssembly Files from the File System. Then browse to...

```text
http://0.0.0.0:8000/index.html
```

And NuttX appears in our Web Browser!

_But something's missing: Where's the Console Input?_

To do Console Input, NuttX needs to support VirtIO Console...

TODO: Pic of VirtIO Console, OpenAMP

# VirtIO Console

_We need Console Input for NuttX Shell..._

_Can't we do it with TinyEMU's HTIF Console?_

HTIF Console supports Polling of Input and Output, __but not Interrupts__. (A bit like [__OpenSBI Console__](https://lupyuen.github.io/articles/sbi#opensbi-debug-console))

To do proper Console Input / Output with Interrupts, we need __VirtIO Console__.

_What's VirtIO?_

[__Virtual I/O Device (VirtIO)__](https://wiki.osdev.org/Virtio) is a Standardised Interface that allows Virtual Machines to access __Consoles, Storage Devices and Network Adapters__. And it works with TinyEMU!

- [__TinyEMU support for VirtIO__](https://bellard.org/tinyemu/readme.txt)

- [__Virtual I/O Device (VirtIO) Spec__](https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html)

_What about NuttX?_

NuttX provides __VirtIO Drivers__, built upon __OpenAMP__...

- [__"Running NuttX with VirtIO on QEMU"__](https://www.youtube.com/watch?v=_8CpLNEWxfo) (YouTube)

- [__"NuttX VirtIO Framework and Future Works"__](https://www.youtube.com/watch?v=CYMkAv-WjQg) (YouTube)

_And OpenAMP is?_

[__Open Asymmetric Multi-Processing (OpenAMP)__](https://www.openampproject.org/) provides the __Message Queue Library__ for VirtIO Guests (like NuttX) to call VirtIO Hosts (like TinyEMU)...

- [__"Introduction to OpenAMP"__](https://www.openampproject.org/docs/whitepapers/Introduction_to_OpenAMPlib_v1.1a.pdf) (Page 4)

We have all the layers, let's assemble our cake and print to VirtIO Console...

1.  Initialise the __VirtIO Console__

1.  Create the __VirtIO Queue__

1.  Send the __VirtIO Message__

_Isn't there a VirtIO Console Driver in NuttX?_

Yeah NuttX has a [__VirtIO Serial Driver__](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c). But let's do it ourselves anyway and discover the inner workings of VirtIO and OpenAMP!

## Initialise the VirtIO Console

_How to make NuttX VirtIO talk to TinyEMU?_

Previously we saw the __TinyEMU Config__ for VirtIO: [riscv_machine.c](https://github.com/fernandotcl/TinyEMU/blob/master/riscv_machine.c#L66-L82)

```c
// VirtIO Settings in TinyEMU
#define VIRTIO_BASE_ADDR 0x40010000
#define VIRTIO_SIZE      0x1000
#define VIRTIO_IRQ       1
```

We copy these VirtIO Settings to __NuttX QEMU__: [qemu_rv_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L41-L49)

```c
// VirtIO Settings in NuttX
#define QEMU_VIRTIO_MMIO_NUM     1  // Number of VirtIO Devices
#define QEMU_VIRTIO_MMIO_BASE    0x40010000
#define QEMU_VIRTIO_MMIO_REGSIZE 0x1000

// TODO: Should VirtIO IRQ be 1? (VIRTIO_IRQ)
#ifdef CONFIG_ARCH_USE_S_MODE  // NuttX Kernel Mode
#  define QEMU_VIRTIO_MMIO_IRQ   26 
#else  // NuttX Flat Mode
#  define QEMU_VIRTIO_MMIO_IRQ   28
#endif
```

__MMIO__ says that NuttX will access VirtIO over __Memory-Mapped I/O__. (Instead of PCI)

With these settings, VirtIO and OpenAMP will start OK on NuttX yay!

```bash
$ temu nuttx.cfg
virtio_mmio_init_device:
  VIRTIO version: 2
  device: 3
  vendor: ffff
```

This means...

- NuttX has validated the [__VirtIO Magic Number__](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L614-L619) from TinyEMU

  (Otherwise NuttX will halt)

- NuttX has detected the [__VirtIO Console__](https://github.com/fernandotcl/TinyEMU/blob/master/virtio.c#L1259-L1361) in TinyEMU

  [(__VirtIO Device__ is 3)](https://wiki.osdev.org/Virtio#Technical_Details)

_How does it work?_

At NuttX Startup: [__board_app_initialize__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L77-L123) calls...

- [__qemu_virtio_register_mmio_devices__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/boards/risc-v/qemu-rv/rv-virt/src/qemu_rv_appinit.c#L54-L73) (to register all VirtIO MMIO Devices) which calls...

- [__virtio_register_mmio_device__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/virtio/virtio-mmio.c#L809-L932) (to register a VirtIO MMIO Device)

Let's create a VirtIO Queue and send some data...

[(__virtio_register_mmio_device__ is explained here)](https://github.com/lupyuen/nuttx-tinyemu#inside-the-virtio-driver-for-nuttx)

## Create the VirtIO Queue

_NuttX VirtIO + OpenAMP are talking OK to TinyEMU. What next?_

To send data to VirtIO Console, we need a __VirtIO Queue__: [virtio-mmio.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/virtio/virtio-mmio.c#L870-L925)

```c
// At Startup: Init VirtIO Device
// Based on virtio_serial_init
// https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L445-L511

// Configure the VirtIO Driver Features
struct virtio_device *vdev = &vmdev->vdev;
virtio_set_status(vdev, VIRTIO_CONFIG_STATUS_DRIVER);
virtio_set_features(vdev, 0);
virtio_set_status(vdev, VIRTIO_CONFIG_FEATURES_OK);

// Configure the 2 VirtQueues: Transmit and Receive
#define VIRTIO_SERIAL_RX  0
#define VIRTIO_SERIAL_TX  1
#define VIRTIO_SERIAL_NUM 2
const char *vqnames[VIRTIO_SERIAL_NUM];
vqnames[VIRTIO_SERIAL_RX] = "virtio_serial_rx";
vqnames[VIRTIO_SERIAL_TX] = "virtio_serial_tx";

// No Callbacks for now
vq_callback callbacks[VIRTIO_SERIAL_NUM];
callbacks[VIRTIO_SERIAL_RX] = NULL;
callbacks[VIRTIO_SERIAL_TX] = NULL;

// Create the VirtQueues: Transmit and Receive
int ret = virtio_create_virtqueues(
  vdev, 0, VIRTIO_SERIAL_NUM, vqnames, callbacks
);

// VirtIO Driver is finally OK!
virtio_set_status(vdev, VIRTIO_CONFIG_STATUS_DRIVER_OK);
```

Now we have 2 VirtIO Queues: __Transmit and Receive__! Let's message them...

[(__virtio_set_status__ comes from OpenAMP)](https://github.com/OpenAMP/open-amp/blob/main/lib/include/openamp/virtio.h#L346-L366)

[(__virtio_create_virtqueues__ too)](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtio.c#L96-L142)

## Send the VirtIO Message

Finally to print something, we write to the __Transmit Queue__: [virtio-mmio.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tinyemu/drivers/virtio/virtio-mmio.c#L870-L925)

```c
// Send data to VirtIO Device
// Based on virtio_serial_dmasend
// https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c#L310-L345

// Get the Transmit VirtQueue
struct virtqueue *vq = vdev->vrings_info[VIRTIO_SERIAL_TX].vq;

// Set the VirtQueue Buffer
static char *HELLO_MSG = "Hello VirtIO from NuttX!\r\n";
struct virtqueue_buf vb[2];
vb[0].buf = HELLO_MSG;
vb[0].len = strlen(HELLO_MSG);
uintptr_t len = strlen(HELLO_MSG);

// Add the Buffer to the Transmit VirtQueue:
// 1 Readable Buffer, 0 Writeable Buffers
virtqueue_add_buffer(
  vq, vb, 1, 0, (void *)len
);

// Notify the VirtIO Host (TinyEMU)
virtqueue_kick(vq);  
```

[(__virtqueue_add_buffer__ comes from OpenAMP)](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L83C1-L138) 

[(__virtqueue_kick__ too)](https://github.com/OpenAMP/open-amp/blob/main/lib/virtio/virtqueue.c#L321-L336)

_What happens when we run this?_

Yep NuttX prints correctly to TinyEMU's VirtIO Console yay! (Pic below)

```bash
$ temu nuttx.cfg
virtio_mmio_init_device: VIRTIO version: 2 device: 3 vendor: ffff
Hello VirtIO from NuttX!
nx_start: CPU0: Beginning Idle Loop
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/8805f8f21dfae237bc06dfbda210628b)

_But still no NuttX Shell?_

We've proven that NuttX VirtIO + OpenAMP will talk OK to [__TinyEMU's VirtIO Console__](https://github.com/lupyuen/nuttx-tinyemu#inside-the-virtio-host-for-tinyemu).

Very soon we shall configure NuttX to use the [__VirtIO Serial Driver__](https://github.com/apache/nuttx/blob/master/drivers/virtio/virtio-serial.c). Then NuttX Shell will appear and we can enter NuttX Commands!

![Apache NuttX RTOS in a Web Browser... With TinyEMU and VirtIO](https://lupyuen.github.io/images/tinyemu-title.png) 

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

# Appendix: Enable VirtIO and OpenAMP in NuttX

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
