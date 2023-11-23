# RISC-V Ox64 BL808 SBC: NuttX Apps and Initial RAM Disk

📝 _30 Nov 2023_

![NuttX App makes a System Call to NuttX Kernel](https://lupyuen.github.io/images/app-title.png)


In Asia the wise folks say...

> _"One can hide on a certain day but cannot hide for a long time"_

> "躲过初一，躲不过十五"

In other words...

> _"Transformers? More than meets the eye!"_

In this article, we go behind the shadow puppetry _(wayang kulit)_ and deceptive simplicity of __NuttX Applications__ inside [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2) (Real-Time Operating System) for [__Pine64 Ox64 BL808 64-bit RISC-V SBC__](https://wiki.pine64.org/wiki/Ox64) (pic below)...

- What's inside the __simplest NuttX App__

- How NuttX Apps make __RISC-V System Calls__ to NuttX Kernel

- __Virtual Memory__ for NuttX Apps

- Loading of __ELF Executables__ by NuttX Kernel

- Bundling of NuttX Apps into the __Initial RAM Disk__

- How we found the __right spot to park__ our Initial RAM Disk

![Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-sbc.jpg)

# Inside a NuttX App

_What happens inside the simplest NuttX App?_

```c
// From https://github.com/apache/nuttx-apps/blob/master/examples/hello/hello_main.c#L36-L40
int main(int argc, FAR char *argv[]) {
  printf("Hello, World!!\n");
  return 0;
}
```

Let's find out! First we build [__NuttX for Ox64 BL808 SBC__](https://lupyuen.github.io/articles/mmu#appendix-build-and-run-nuttx).

Which produces this __ELF Executable__ for our NuttX App...

```bash
## ELF Executable for `hello` looks big...
$ ls -l ../apps/bin/hello
-rwxr-xr-x  518,192  ../apps/bin/hello

## Though not much inside, mostly Debug Info...
$ riscv64-unknown-elf-size ../apps/bin/hello
   text  data  bss   dec  hex  filename
   3814     8    4  3826  ef2  ../apps/bin/hello

## Dump the RISC-V Disassembly to `hello.S`
$ riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  ../apps/bin/hello \
  >hello.S \
  2>&1
```

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64a-1)

Here's the __RISC-V Disassembly__ of our NuttX App: [hello.S](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/ox64a-1/hello.S)

```text
## Omitted: _start() prepares for signals (sig_trampoline) and calls main()

003e <main>:
int main(int argc, FAR char *argv[]) {
  3e: 1141      addi   sp,sp,-16  ## Subtract 16 from Stack Pointer

## Set Register A0 (Arg 0) to "Hello, World!!\n"
  40: 00000517  auipc  a0,0x0    40: R_RISCV_PCREL_HI20    .LC0
  44: 00050513  mv     a0,a0     44: R_RISCV_PCREL_LO12_I  .L0 

printf("Hello, World!!\n");
  48: e406      sd     ra,8(sp)  ## Save Return Address to Stack Pointer, Offset 8
  4a: 00000097  auipc  ra,0x0    4a: R_RISCV_CALL  puts
  4e: 000080e7  jalr   ra      # 4a <.LVL1+0x2>  ## Call puts()

return 0;
  52: 60a2      ld    ra,8(sp)  ## Load Return Address from Stack Pointer, Offset 8
  54: 4501      li    a0,0      ## Set Return Value to 0
  56: 0141      addi  sp,sp,16  ## Add 16 to Stack Pointer
  58: 8082      ret             ## Return to caller: _start()

## Followed by the code for puts(), lib_fwrite_unlocked(), write(), ...
```

In the RISC-V Disassembly, we see that [__main__](https://github.com/apache/nuttx-apps/blob/master/examples/hello/hello_main.c#L36-L40) calls...

- [__puts__](https://github.com/apache/nuttx/blob/master/libs/libc/stdio/lib_puts.c#L34-L96), which calls...

- [__lib_fwrite_unlocked__](https://github.com/apache/nuttx/blob/master/libs/libc/stdio/lib_libfwrite.c#L45-L200), which calls...

- [__write__](https://github.com/apache/nuttx/blob/master/libs/libc/stdio/lib_libfwrite.c#L149), which calls...

- __NuttX Kernel__ to print "Hello World"

How will [__write__](https://github.com/apache/nuttx/blob/master/libs/libc/stdio/lib_libfwrite.c#L149) call the NuttX Kernel? We'll see soon!

_This code doesn't look right..._

```text
printf("Hello, World!!\n");

  ## Load Register RA with Program Counter + 0x0
  4a: 00000097  auipc  ra, 0x0

  ## Call the function in Register RA: puts()
  4e: 000080e7  jalr   ra
```

We break it down...

- [__`auipc`__](https://five-embeddev.com/quickref/instructions.html#-rv32--integer-register-immediate-instructions) sets Register RA to...

  ```c
  Program Counter + 0x0
  ```

- [__`jalr`__](https://five-embeddev.com/quickref/instructions.html#-rv32--unconditional-jumps) jumps to the Function pointed by Register RA...

  Which we expect to be [__puts__](https://github.com/apache/nuttx/blob/master/libs/libc/stdio/lib_puts.c#L34-L96)

_Shouldn't `auipc` add the Offset of `puts`?_

Ah that's because we're looking at [__Relocatable Code__](https://en.wikipedia.org/wiki/Relocation_(computing))!

The __`auipc`__ Offset will be fixed up by the __NuttX ELF Loader__ when it loads our NuttX App for execution.

In our RISC-V Disassembly, the __Relocation Info__ shows that __`0x0`__ will be replaced by the Offset of [__puts__](https://github.com/apache/nuttx/blob/master/libs/libc/stdio/lib_puts.c#L34-L96)...

```text
printf("Hello, World!!\n");

  ## Load Register RA with Program Counter + 0x0...
  ## Actually 0x0 will be changed to the Offset of puts()
  4a: 00000097  auipc  ra, 0x0  
  4a: R_RISCV_CALL     puts

  ## Call the function in Register RA: puts()
  ## Which will work when ELF Loader fixes the Offset of puts()
  4e: 000080e7  jalr   ra     # 4a <.LVL1+0x2>
```

Therefore we're all good!

_Why `puts` instead of `printf`?_

The GCC Compiler has cleverly optimised away __printf__ to become __puts__.

If we do this (and foil the GCC Compiler)...

```c
// Nope, GCC Compiler won't change printf() to puts()
printf(
  "Hello, World %s!!\n",  // Meaningful Format String
  "Luppy"                 // Makes it complicated
);
```

Then __printf__ will appear in our RISC-V Disassembly.

We circle back to __write__...

![NuttX App calls NuttX Kernel](https://lupyuen.github.io/images/app-syscall.jpg)

# NuttX App calls NuttX Kernel

_Our app will print something to the Console Output..._

_But NuttX Apps can't write directly to the Serial Device right?_

Nope! NuttX Apps run in __RISC-V User Mode__...

Which doesn't have access to Serial Device and other resources controlled by NuttX Kernel. (Running in __RISC-V Supervisor Mode__)

That's why "__write__" will trigger a __System Call__ to the NuttX Kernel, jumping from RISC-V __User Mode to Supervisor Mode__.

(And write to the Serial Device, pic above)

_Will NuttX Apps need Special Coding to make System Calls?_

Nope! The System Call is __totally transparent__ to our app...

- Our __NuttX App__ will call a normal function named "__write__"...

- That pretends to be the actual "__write__" function in __NuttX Kernel__...

- By forwarding the "__write__" function call (and parameters)...

- Through a __RISC-V System Call__

_What's this "forwarding" to a System Call?_

This forwarding happens inside a __Proxy Function__ that's auto-generated during NuttX Build...

```c
// From nuttx/syscall/proxies/PROXY_write.c
// Auto-Generated Proxy for `write`
// Looks like the Kernel `write`, though it's actually a System Call
ssize_t write(int parm1, FAR const void * parm2, size_t parm3) {
  return (ssize_t) sys_call3(  // Make a System Call with 3 parameters...
    (unsigned int) SYS_write,  // System Call Number (63 = `write`)
    (uintptr_t) parm1,         // File Descriptor (1 = Standard Output)
    (uintptr_t) parm2,         // Buffer to be written
    (uintptr_t) parm3          // Number of bytes to write
  );
}
```

Our NuttX App calls this __Proxy Version__ of "__write__" (that pretends to be the Kernel "__write__")...

```c
// Our App calls the Proxy Function...
int ret = write(
  1,  // File Descriptor (1 = Standard Output)
  "Hello, World!!\n",  // Buffer to be written
  15  // Number of bytes to write
);
```

Which triggers a __System Call__ to the Kernel.

_What's sys_call3?_

It makes a __System Call__ (to NuttX Kernel) with __3 Parameters__: [syscall.h](https://github.com/apache/nuttx/blob/master/arch/risc-v/include/syscall.h)

```c
// Make a System Call with 3 parameters
uintptr_t sys_call3(
  unsigned int nbr,  // System Call Number (63 = `write`)
  uintptr_t parm1,   // First Parameter
  uintptr_t parm2,   // Second Parameter
  uintptr_t parm3    // Third Parameter
) {
  // Pass the Function Number and Parameters in
  // Registers A0 to A3
  register long r0 asm("a0") = (long)(nbr);
  register long r1 asm("a1") = (long)(parm1);
  register long r2 asm("a2") = (long)(parm2);
  register long r3 asm("a3") = (long)(parm3);

  // `ecall` will jump from RISC-V User Mode
  // to RISC-V Supervisor Mode
  // to execute the System Call.
  // Input+Output Registers: A0 to A3
  // Clobbers the Memory
  asm volatile
  (
    "ecall"
    :: "r"(r0), "r"(r1), "r"(r2), "r"(r3)
    : "memory"
  );

  // No-operation, does nothing
  asm volatile("nop" : "=r"(r0));

  // Return the result from Register A0
  return r0;
}
```

[__`ecall`__](https://five-embeddev.com/quickref/instructions.html#-rv32--rv32) is the RISC-V Instruction that triggers a jump from RISC-V __User Mode to Supervisor Mode__...

Such that NuttX Kernel can execute the actual "__write__" function, with the real Serial Device.

(We'll explain how)

_Why the no-op after ecall?_

We're guessing: It might be reserved for special calls to NuttX Kernel in future.

[(Similar to __`ebreak`__ for Semihosting)](https://lupyuen.github.io/articles/semihost#decipher-the-risc-v-exception)

_Every System Call to NuttX Kernel has its own Proxy Function?_

Yep we can see the list of Auto-Generated __Proxy Functions__ for each System Call...

```bash
## Proxy Functions called by `hello` app
$ grep PROXY hello.S
PROXY__assert.c
PROXY__exit.c
PROXY_clock_gettime.c
PROXY_gettid.c
PROXY_lseek.c
PROXY_nxsem_wait.c
PROXY_sem_clockwait.c
PROXY_sem_destroy.c
PROXY_sem_post.c
PROXY_sem_trywait.c
PROXY_task_setcancelstate.c
PROXY_write.c
```

Next we figure out how System Calls will work...

![NuttX Kernel handles System Call](https://lupyuen.github.io/images/app-syscall2.jpg)

# NuttX Kernel handles System Call

_Our App makes an ecall to jump to NuttX Kernel..._

_What happens on the other side?_

Remember the Proxy Function from earlier? Now we do the exact opposite in our __Stub Function__ (that runs in the Kernel)...

```c
// From nuttx/syscall/stubs/STUB_write.c
// Auto-Generated Stub File for `write`
// This runs in NuttX Kernel triggered by `ecall`.
// We make the actual call to `write`.
// (`nbr` is Offset in Stub Lookup Table, unused)
uintptr_t STUB_write(int nbr, uintptr_t parm1, uintptr_t parm2, uintptr_t parm3) {
  return
    (uintptr_t) write(  // Call the Kernel version of `write`
      (int) parm1,      // File Descriptor (1 = Standard Output)
      (FAR const void *) parm2,  // Buffer to be written
      (size_t) parm3    // Number of bytes to write
    );                  // Return the result to the App
}
```

Thus our __NuttX Build__ auto-generates 2 things...

- __Proxy Function__ (runs in NuttX Apps)

- __Stub Function__ (runs in NuttX Kernel)

This happens for __every System Call__ exposed by NuttX Kernel.

```bash
## Stub Functions in NuttX Kernel
$ grep STUB nuttx.S
STUB__assert.c
STUB__exit.c
STUB_boardctl.c
STUB_chmod.c
STUB_chown.c
...
```

[(More about __Proxy and Stub Functions__)](https://nuttx.apache.org/docs/latest/components/syscall.html)

_Who calls STUB_write?_

When our NuttX App makes an __`ecall`__, it triggers __IRQ 8__ [__(RISCV_IRQ_ECALLU)__](https://github.com/apache/nuttx/blob/master/arch/risc-v/include/irq.h#L52-L75) that's [__handled by__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_exception.c#L114-L119)...

- [__riscv_swint__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_swint.c#L105-L537), which calls...

- [__dispatch_syscall__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_swint.c#L54-L100), which calls the Kernel Stub Function (__STUB_write__) and... 

  [__sys_call2__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/supervisor/riscv_syscall.S#L49-L177) with A0 set to __SYS_syscall_return__ (3), which calls...

- [__riscv_perform_syscall__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/supervisor/riscv_perform_syscall.c#L36-L78), which calls...

- [__riscv_swint__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_swint.c#L105-L537) with IRQ 0, to return from the __`ecall`__

_How will dispatch_syscall know which Stub Function to call?_

Remember that our Proxy Function (in NuttX App) will pass the __System Call Number__ for "__write__"?

```c
// From nuttx/syscall/proxies/PROXY_write.c
// Auto-Generated Proxy for `write`, called by NuttX App
ssize_t write(int parm1, FAR const void * parm2, size_t parm3) {
  return (ssize_t) sys_call3(  // Make a System Call with 3 parameters...
    (unsigned int) SYS_write,  // System Call Number (63 = `write`)
    ...
```

[__dispatch_syscall__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_swint.c#L54-L100) (in NuttX Kernel) will look up the System Call Number in the [__Stub Lookup Table__](https://github.com/apache/nuttx/blob/master/syscall/syscall_stublookup.c#L80-L93). And fetch the __Stub Function__ to call.

_How did we figure out that 63 is the System Call Number for "write"?_

OK this part gets tricky. Below is the Enum that defines all __System Call Numbers__: [syscall.h](https://github.com/apache/nuttx/blob/master/include/sys/syscall.h#L55-L66) and [syscall_lookup.h](https://github.com/apache/nuttx/blob/master/include/sys/syscall_lookup.h#L202)

```c
// System Call Enum sequentially assigns
// all System Call Numbers (8 to 147-ish)
enum {
  ...
  SYSCALL_LOOKUP(close, 1)
  SYSCALL_LOOKUP(ioctl, 3)
  SYSCALL_LOOKUP(read,  3)
  SYSCALL_LOOKUP(write, 3)
  ...
};
```

However it's an Enum, __numbered sequentially__ from 8 to 147-ish. We won't literally see 63 in the NuttX Source Code.

Then we lookup the __Debug Info__ in the RISC-V Disassembly for NuttX Kernel: [nuttx.S](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/ox64a-1/nuttx.S)

```text
Abbrev Number: 6 (DW_TAG_enumerator)
  DW_AT_name        : SYS_write
  DW_AT_const_value : 63
```

Whoomp there it is! This says that "__write__" is __System Call #63__.

_That's an odd way to define System Call Numbers..._

Yeah it's __not strictly an immutable ABI__ like Linux, because our System Call Numbers may change! It depends on the [__Build Options__](https://github.com/apache/nuttx/blob/master/include/sys/syscall_lookup.h#L90-L152) that we select.

[(ABI means __Application Binary Interface__)](https://en.wikipedia.org/wiki/Application_binary_interface)

Though there's a jolly good thing: It's super simple to experiment with __new System Calls__!

[(Just add to __NuttX System Calls__)](https://github.com/apache/nuttx/blob/master/syscall/syscall.csv#L209-L210)

[(As explained here)](https://nuttx.apache.org/docs/latest/components/syscall.html)

![NuttX App calls NuttX Kernel](https://lupyuen.github.io/images/app-run.png)

# System Call in Action

_This looks complicated... It works right?_

Yep we have solid evidence, from [__NuttX for Ox64 BL808 SBC__](https://lupyuen.github.io/articles/mmu#appendix-build-and-run-nuttx)!

Remember to enable __System Call Logging__ in "`make menuconfig`"...

```text
Build Setup 
  > Debug Options 
    > Syscall Debug Features 
      > Syscall Warning / Error / Info
```

Our app (NuttX Shell) is printing something to the console. (Pic above)

It makes an __`ecall`__ for System Call #63 "__write__", which triggers __IRQ 8__...

```text
riscv_dispatch_irq: irq=8
riscv_swint: Entry: regs: 0x5040bcb0 cmd: 63
EPC: 800019b2
A0: 003f A1: 0001 A2: 8000ad00 A3: 001e
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/ce82b29c664b1d5898b6a59743310c17)

And jumps to NuttX Kernel. The __RISC-V Registers__ look familiar...

- A0 is __`0x3F`__

  (System Call #63 for "__write__")

- A1 is __`1`__

  (File Descriptor #1 for Standard Output)

- A2 is __`0x8000_AD00`__

  (Buffer to be written)

- A3 is __`0x1E`__

  (Number of bytes to write)

NuttX Kernel calls our Stub Function __STUB_write__...

```text
riscv_swint: SWInt Return: 37
STUB_write: nbr=440, parm1=1, parm2=8000ad00, parm3=1e
NuttShell (NSH) NuttX-12.0.3
```

Which calls Kernel "__write__" and __prints the text__: "NuttShell"

Then NuttX Kernel completes the __`ecall`__...

```text
riscv_swint: Entry: regs: 0x5040baa0 cmd: 3
EPC: 80001a6a
A0: 0003 A1: 5040bbec A2: 001e A3: 0000
riscv_swint: SWInt Return: 1e
```

- A0 is __3__

  (Return from System Call: [__SYS_syscall_return__](https://github.com/apache/nuttx/blob/master/arch/risc-v/include/syscall.h#L80-L87))

- A2 is __`0x1E`__

  (Number of bytes written)

And returns the result __`0x1E`__ to our NuttX App.

NuttX successfully makes a System Call on Ox64 SBC yay! (Pic above)

[(See the __Complete Log__)](https://gist.github.com/lupyuen/ce82b29c664b1d5898b6a59743310c17)

![Virtual Memory for NuttX App](https://lupyuen.github.io/images/mmu-l3user.jpg)

[_Virtual Memory for NuttX App_](https://lupyuen.github.io/articles/mmu#virtual-memory)

# Kernel Accesses App Memory

_NuttX Kernel prints the buffer at `0x8000_AD00`..._

_It doesn't look like a RAM Address?_

That's a __Virtual Memory Address__...

- [__"RISC-V Ox64 BL808 SBC: Sv39 Memory Management Unit"__](https://lupyuen.github.io/articles/mmu)

TLDR? No worries...

- __Kernel RAM__ is at __`0x5000_0000`__

- Which gets dished out dynamically to __NuttX Apps__

- And becomes __Virtual Memory__ at __`0x8000_0000`__ (pic above)

Thus our NuttX App has passed a chunk of its own __Virtual Memory__. And NuttX Kernel happily prints it!

_Huh? NuttX Kernel can access Virtual Memory?_

1.  NuttX uses 2 sets of Page Tables: __Kernel Page Table__ and __User Page Table__.

    (User Page Table defines the __Virtual Memory__ for NuttX Apps)

1.  According to the [__NuttX Log__](https://gist.github.com/lupyuen/ce82b29c664b1d5898b6a59743310c17), the Kernel swaps the [__RISC-V SATP Register__](https://lupyuen.github.io/articles/mmu#swap-the-satp-register) from Kernel Page Table to __User Page Table__...

    And doesn't swap back!

1.  Which means the __User Page Table__ is still in effect!

    Thus the __Virtual Memory__ at __`0x8000_0000`__ is perfectly accessible by the Kernel.

1.  There's a catch: __RISC-V Supervisor Mode__ (NuttX Kernel) may access the Virtual Memory mapped to __RISC-V User Mode__ (NuttX Apps)...

    Only if the [__SUM Bit is set in SSTATUS Register__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:translation)!

1.  And that's absolutely hunky dory because at NuttX Startup, [__nx_start__](https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L298-L713) calls...

    [__up_initial_state__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_initialstate.c#L41-L140), which calls...

    [__riscv_set_idleintctx__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_getnewintctx.c#L74-L81) to set the __SUM Bit__ in SSTATUS Register

    [(Who calls __nx_start__)](https://lupyuen.github.io/articles/ox2#appendix-nuttx-boot-flow)

That's why NuttX Kernel can access Virtual Memory (passed by NuttX Apps) at __`0x8000_0000`__!

![Kernel Starts a NuttX App](https://lupyuen.github.io/images/app-flow.jpg)

[_Clickable Version of NuttX Flow_](https://github.com/lupyuen/nuttx-ox64#kernel-starts-a-nuttx-app)

# Kernel Starts a NuttX App

_Alrighty NuttX Apps can call NuttX Kernel..._

_But how does NuttX Kernel start a NuttX App?_

Earlier we stepped through the __Boot Sequence__ for NuttX...

- [__"NuttX Boot Flow"__](https://lupyuen.github.io/articles/ox2#appendix-nuttx-boot-flow)

Right after that, [__NuttX Bringup (nx_bringup)__](https://github.com/apache/nuttx/blob/master/sched/init/nx_bringup.c#L373-L458) calls (pic above)...

- [__Create Init Thread: nx_create_initthread__](https://github.com/apache/nuttx/blob/master/sched/init/nx_bringup.c#L330-L367) (to create the Init Thread), which calls...

- [__Start App: nx_start_application__](https://github.com/apache/nuttx/blob/master/sched/init/nx_bringup.c#L212C1-L302) (to start NuttX Shell), which calls...

- [__Exec Spawn: exec_spawn__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_exec.c#L183-L223) (to start the app), which calls...

- [__Exec Internal: exec_internal__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_exec.c#L42-L179) (to start the app), which calls...

- [__Load Module: load_module__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_loadmodule.c#L136-L225) (to load the app, see below) and...

  [__Execute Module: exec_module__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_execmodule.c#L190-L450) (to execute the app)

To load a NuttX App module: [__load_module__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_loadmodule.c#L136-L225) calls...

- [__Load Absolute Module: load_absmodule__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_loadmodule.c#L83-L132) (to load an absolute path), which calls...

- [__Load Binary Format: binfmt_s.load__](https://github.com/apache/nuttx/blob/master/include/nuttx/binfmt/binfmt.h#L122-L148) (to load a binary module), which calls...

- [__ELF Loader: g_elfbinfmt__](https://github.com/apache/nuttx/blob/master/binfmt/elf.c#L84-L94) (to load the ELF File, see below)

To load the ELF File: [__ELF Loader g_elfbinfmt__](https://github.com/apache/nuttx/blob/master/binfmt/elf.c#L84-L94) calls...

- [__Load ELF Binary: elf_loadbinary__](https://github.com/apache/nuttx/blob/master/binfmt/elf.c#L225-L355) (to load the ELF Binary), which calls...

- [__Load ELF: elf_load__](https://github.com/apache/nuttx/blob/master/binfmt/libelf/libelf_load.c#L297-L445) (to load the ELF Binary), which calls...

- [__Allocate Address Env: elf_addrenv_alloc__](https://github.com/apache/nuttx/blob/master/binfmt/libelf/libelf_addrenv.c#L56-L178) (to allocate the Address Env), which calls...

- [__Create Address Env: up_addrenv_create__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_addrenv.c#L339-L490) (to create the Address Env), which calls...

  (Also calls [__mmu_satp_reg__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_mmu.h#L152-L176) to set SATP Register)

- [__Create MMU Region: create_region__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_addrenv.c#L213-L310) (to create the MMU Region), which calls...

- [__Set MMU Page Table Entry: mmu_ln_setentry__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_mmu.c#L62-L109) (to populate the Page Table Entries)

There's plenty happening inside [__Execute Module: exec_module__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_execmodule.c#L190-L450). Too bad we won't explore today.

[(__Clickable Version__ of NuttX Flow)](https://github.com/lupyuen/nuttx-ox64#kernel-starts-a-nuttx-app)

![Initial RAM Disk for Star64 JH7110](https://lupyuen.github.io/images/semihost-title.jpg)

[_Initial RAM Disk for Star64 JH7110_](https://lupyuen.github.io/articles/semihost)

# Initial RAM Disk

_OK we know how NuttX Kernel starts a NuttX App..._

_But where are the NuttX Apps stored?_

Right now we're working with the __Early Port of NuttX__ to Ox64 BL808 SBC. We can't access the File System in the microSD Card.

All we have: A File System that __lives in RAM__ and contains our NuttX Shell + NuttX Apps. That's our __Initial RAM Disk: initrd__.

```bash
## Build the Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd

## Generate the Initial RAM Disk `initrd`
## in ROMFS Filesystem Format
## from the Apps Filesystem `../apps/bin`
## and label it `NuttXBootVol`
genromfs \
  -f initrd \
  -d ../apps/bin \
  -V "NuttXBootVol"
```

_How to load the Initial RAM Disk from microSD to RAM?_

[__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64) will do it for us! Two ways we can load the Initial RAM Disk from microSD...

1.  Load the Initial RAM Disk from a __Separate File: initrd__ (similar to Star64, pic above)

    This means we need to modify the [__U-Boot Script: boot-pine64.scr__](https://github.com/openbouffalo/buildroot_bouffalo/blob/main/board/pine64/ox64/boot-pine64.cmd)

    And make it [__load the initrd__](https://lupyuen.github.io/articles/semihost#appendix-boot-nuttx-over-tftp-with-initial-ram-disk) file into RAM.

    (Which is good for separating the NuttX Kernel and NuttX Apps)

    OR...

1.  Append the Initial RAM Disk to the __NuttX Kernel Image__

    U-Boot Bootloader will load (one-shot into RAM) the NuttX Kernel + Initial RAM Disk.
    
    And we reuse the existing __U-Boot Config__ on the microSD Card: [__extlinux/extlinux.conf__](https://github.com/openbouffalo/buildroot_bouffalo/blob/main/board/pine64/ox64/rootfs-overlay/boot/extlinux/extlinux.conf)

    (Which might be more efficient for our Limited RAM)

    [(More about the __U-Boot Boot Flow__)](https://github.com/openbouffalo/buildroot_bouffalo/wiki/U-Boot-Bootflow)

We'll do the Second Method, since we are low on RAM. Like this...

```bash
## Export the NuttX Kernel to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.zero

## Append Padding and Initial RAM Disk to NuttX Kernel
cat nuttx.bin /tmp/nuttx.zero initrd \
  >Image

## Overwrite the Linux Image on Ox64 microSD
cp Image "/Volumes/NO NAME/"

## U-Boot Bootloader will load NuttX Kernel and
## Initial RAM Disk into RAM
```

Let's make this work...

![Initial RAM Disk for Ox64](https://lupyuen.github.io/images/app-initrd.jpg)

# Mount the Initial RAM Disk

_How will NuttX Kernel locate the Initial RAM Disk in RAM?_

Our Initial RAM Disk is in [__ROM File System Format__](https://docs.kernel.org/filesystems/romfs.html).

We __search our RAM__ for the ROM File System, then copy it into the designated __Memory Region__: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L190-L245)

```c
// Locate the Initial RAM Disk and copy to the designated Memory Region
void jh7110_copy_ramdisk(void) {

  // After _edata, search for "-rom1fs-". This is the RAM Disk Address.
  // Limit search to 256 KB after Idle Stack Top.
  const char *header = "-rom1fs-";
  uint8_t *ramdisk_addr = NULL;
  for (uint8_t *addr = _edata; addr < (uint8_t *)JH7110_IDLESTACK_TOP + (256 * 1024); addr++) {
    if (memcmp(addr, header, strlen(header)) == 0) {
      ramdisk_addr = addr;
      break;
    }
  }

  // Stop if RAM Disk is missing
  DEBUGASSERT(ramdisk_addr != NULL);

  // RAM Disk must be after Idle Stack, to prevent overwriting
  DEBUGASSERT(ramdisk_addr > (uint8_t *)JH7110_IDLESTACK_TOP);

  // Read the Filesystem Size from the next 4 bytes, in Big Endian
  // Add 0x1F0 to Filesystem Size
  const uint32_t size =
    (ramdisk_addr[8] << 24) + 
    (ramdisk_addr[9] << 16) + 
    (ramdisk_addr[10] << 8) + 
    ramdisk_addr[11] + 
    0x1F0;

  // Filesystem Size must be less than RAM Disk Memory Region
  DEBUGASSERT(size <= (size_t)__ramdisk_size);

  // Copy the Filesystem bytes to RAM Disk Start
  // Warning: __ramdisk_start overlaps with ramdisk_addr + size
  // Which doesn't work with memcpy.
  // Sadly memmove is aliased to memcpy, so we implement memmove ourselves
  local_memmove((void *)__ramdisk_start, ramdisk_addr, size);
}
```

_Why did we copy Initial RAM Disk to ramdisk_start?_

__ramdisk_start__ points to the Memory Region that we reserved for mounting our RAM Disk. It's defined in the __NuttX Linker Script__: [ld.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L21-L48)

```text
/* Memory Region for RAM Disk */
ramdisk (rwx) : ORIGIN = 0x50A00000, LENGTH = 16M
...
__ramdisk_start = ORIGIN(ramdisk);
__ramdisk_size = LENGTH(ramdisk);
__ramdisk_end  = ORIGIN(ramdisk) + LENGTH(ramdisk);
```

_Who calls the code above?_

We locate and copy the Initial RAM Disk at the very top of our __NuttX Start Code__. 

This happens before erasing the BSS, in case it corrupts our RAM Disk: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L144-L156)

```c
// NuttX Start Code
void jh7110_start(int mhartid) {

  // Copy the RAM Disk
  jh7110_copy_ramdisk();

  // Clear the BSS
  jh7110_clear_bss();
```

(BSS shouldn't matter, as explained below)

Later during startup, we __mount the RAM Disk__ from the Memory Region : [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L51-L87)

```c
// After NuttX has booted...
void board_late_initialize(void) {
  // Mount the RAM Disk
  mount_ramdisk();
}

// Mount the RAM Disk
int mount_ramdisk(void) {
  desc.minor    = RAMDISK_DEVICE_MINOR;
  desc.nsectors = NSECTORS((ssize_t)__ramdisk_size);
  desc.sectsize = SECTORSIZE;
  desc.image    = __ramdisk_start;
  ret = boardctl(BOARDIOC_ROMDISK, (uintptr_t)&desc);
```

And NuttX mounts our RAM Disk successfully!

```text
jh7110_copy_ramdisk: _edata=0x50400258, _sbss=0x50400290, _ebss=0x50407000, JH7110_IDLESTACK_TOP=0x50407c00
jh7110_copy_ramdisk: ramdisk_addr=0x50408288
jh7110_copy_ramdisk: size=8192016
jh7110_copy_ramdisk: Before Copy: ramdisk_addr=0x50408288
jh7110_copy_ramdisk: After Copy: __ramdisk_start=0x50a00000
...
elf_initialize: Registering ELF
uart_register: Registering /dev/console
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
load_absmodule: Loading /system/bin/init
elf_loadbinary: Loading file: /system/bin/init
elf_init: filename: /system/bin/init loadinfo: 0x5040c618
elf_read: Read 64 bytes from offset 0
```

[(Source)](https://gist.github.com/lupyuen/74a44a3e432e159c62cc2df6a726cb89)

Last thing for today: The mysterious 64 KB padding...

![Initial RAM Disk for Ox64](https://lupyuen.github.io/images/app-initrd2.jpg)

# Pad the Initial RAM Disk

_Between NuttX Kernel and Initial RAM Disk..._

_Why did we pad 64 KB of zeroes?_

```bash
## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.zero

## Append Padding and Initial RAM Disk to NuttX Kernel
cat nuttx.bin /tmp/nuttx.zero initrd \
  >Image

## U-Boot Bootloader will load NuttX Kernel and
## Initial RAM Disk into RAM
```

U-Boot Bootloader will load our Initial RAM Disk into RAM, dangerously close to __BSS Memory__ (Global and Static Variables) and __Kernel Stack__.

There's a risk that our Initial RAM Disk will be __contaminated by BSS and Stack__. This is how we found a clean, safe space for our Initial RAM Disk...

When we refer to the [__NuttX Log__](https://gist.github.com/lupyuen/74a44a3e432e159c62cc2df6a726cb89) and the [__NuttX Linker Script__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script)...

```text
// End of Data Section
_edata=0x50400258

// Start of BSS Section
_sbss=0x50400290

// End of BSS Section
_ebss=0x50407000

// Top of Kernel Idle Stack
JH7110_IDLESTACK_TOP=0x50407c00

// We located the initrd after the Top of Idle Stack
ramdisk_addr=0x50408288, size=8192016

// And we copied initrd to the Memory Region for the RAM Disk
__ramdisk_start=0x50a00000
```

Or graphically...

| Memory Region | Start | End |
|:--------------|:-----:|:---:|
| __Data Section__ | | `0x5040_0257`
| __BSS Section__ | `0x5040_0290` | `0x5040_6FFF`
| __Kernel Idle Stack__ | | `0x5040_7BFF`
| __Initial RAM Disk__ | `0x5040_8288` | `0x50BD_8297`
| __RAM Disk Region__ | `0x50A0_0000` | `0x519F_FFFF`

(NuttX will mount the RAM Disk from __RAM Disk Region__)

(Which overlaps with __Initial RAM Disk__!)

Which says...

1.  NuttX Kernel __`nuttx.bin`__ terminates at __`edata`__.

    (End of Data Section)

1.  If we append Initial RAM Disk __`initrd`__ directly to the end of __`nuttx.bin`__...

    It will collide with the [__BSS Section__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L74-L92) and the [__Kernel Idle Stack__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_head.S#L94-L101).

    And __`initrd`__ will get overwritten by the Boot Code and Start Code.

1.  Best place to append __`initrd`__ is after the __Kernel Idle Stack__.

    Which is located 32 KB after __`edata`__.
    
1.  That's why we inserted a padding of 64 KB between __`nuttx.bin`__ and __`initrd`__.

    (To be sure it won't collide with BSS and Kernel Idle Stack)

1.  Our code locates __`initrd`__. (Searching for ROM FS Magic Number "-rom1fs-")

    And copies __`initrd`__ to __RAM Disk Region__.
    
1.  Finally NuttX mounts the RAM Disk from __RAM Disk Region__.

Yep our 64 KB Padding looks legit!

_64 KB sounds arbitrary. What if the parameters change?_

That's why we have __Runtime Checks__: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L190-L245)

```c
// Stop if RAM Disk is missing
if (ramdisk_addr == NULL) { _info("Missing RAM Disk. Check the initrd padding."); }
DEBUGASSERT(ramdisk_addr != NULL);

// RAM Disk must be after Idle Stack, to prevent overwriting
if (ramdisk_addr <= (uint8_t *)JH7110_IDLESTACK_TOP) { _info("RAM Disk must be after Idle Stack. Increase the initrd padding by %ul bytes.", (size_t)JH7110_IDLESTACK_TOP - (size_t)ramdisk_addr); }
DEBUGASSERT(ramdisk_addr > (uint8_t *)JH7110_IDLESTACK_TOP);

// Filesystem Size must be less than RAM Disk Memory Region
DEBUGASSERT(size <= (size_t)__ramdisk_size);
```

_Why call local_memmove to copy initrd to RAM Disk Region? Why not memcpy?_

That's because __`initrd`__ overlaps with __RAM Disk Region__! (See above)

__`memcpy`__ won't work with __Overlapping Memory Regions__. Thus we added this: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L246-L487)

```c
// Copy a chunk of memory from `src` to `dest`.
// `dest` overlaps with the end of `src`.
// From libs/libc/string/lib_memmove.c
void *local_memmove(void *dest, const void *src, size_t count) {
  DEBUGASSERT(dest > src);
  char *d = (char *) dest + count;
  char *s = (char *) src + count;
  // TODO: This needs to be `volatile` or GCC Compiler will replace this by memcpy. Very strange. 
  while (count--) {
    d -= 1; s -= 1;
    volatile char c = *s;
    *d = c;
  }
  return dest;
}
```

_We're sure that it works?_

We called __`verify_image`__ to do a simple integrity check on __`initrd`__, before and after copying: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L246-L487)

```c
// Before Copy: Verify the RAM Disk Image to be copied
verify_image(ramdisk_addr);

// Copy the Filesystem Size to RAM Disk Start
// Warning: __ramdisk_start overlaps with ramdisk_addr + size
// Which doesn't work with memcpy.
// Sadly memmove is aliased to memcpy, so we implement memmove ourselves
local_memmove((void *)__ramdisk_start, ramdisk_addr, size);

// After Copy: Verify the copied RAM Disk Image
verify_image(__ramdisk_start);
```

[(__`verify_image`__ does a simple Integrity Check)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L248-L455)

That's how we discovered that __`memcpy`__ doesn't work. And our __`local_memmove`__ works great! (Pic below)

![Ox64 boots to NuttX Shell](https://lupyuen.github.io/images/mmu-boot1.png)

[_Ox64 boots to NuttX Shell_](https://gist.github.com/lupyuen/aa9b3e575ba4e0c233ab02c328221525)

# What's Next

TODO

Like we said at the top of the article...

> _"One can hide on the First... But can't hide on the Fifteenth!"_

Today we unravelled the inner workings of __NuttX Applications__ for __Ox64 BL808 RISC-V SBC__...

TODO

We'll do much more for __NuttX on Ox64 BL808__, stay tuned for updates!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/app.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/app.md)
