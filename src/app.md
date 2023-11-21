# RISC-V Ox64 BL808 SBC: NuttX Apps and Initial RAM Disk

📝 _30 Nov 2023_

![TODO](https://lupyuen.github.io/images/app-title.png)

TODO

[__Pine64 Ox64 64-bit RISC-V SBC__](https://wiki.pine64.org/wiki/Ox64). (Pic below)

(Powered by [__Bouffalo Lab BL808 SoC__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf))

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2). (Real-Time Operating System)

![Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-sbc.jpg)

# Inside a NuttX App

_What happens inside the simplest NuttX App?_

```c
// From https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/ox64b/examples/hello/hello_main.c#L36-L40
int main(int argc, FAR char *argv[]) {
  printf("Hello, World!!\n");
  return 0;
}
```

Let's find out! We build [__NuttX for Ox64 BL808 SBC__](https://lupyuen.github.io/articles/mmu#appendix-build-and-run-nuttx).

Which produces this __ELF Executable__ for our NuttX App...

```bash
## ELF Executable for `hello` looks big...
$ ls -l ../apps/bin/hello
-rwxr-xr-x  518,192  ../apps/bin/hello

## But not much inside, mostly Debug Info...
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

In the RISC-V Disassembly, we see that [__main__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/ox64b/examples/hello/hello_main.c#L36-L40) calls...

- [__puts__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_puts.c#L34-L96), which calls...

- [__lib_fwrite_unlocked__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_libfwrite.c#L45-L200), which calls...

- [__write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_libfwrite.c#L149), which calls...

- __NuttX Kernel__ to print "Hello World"

How will [__write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_libfwrite.c#L149) call the NuttX Kernel? We'll see soon!

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

  Which we expect to be [__puts__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_puts.c#L34-L96)

_Shouldn't `auipc` add the Offset of `puts`?_

Ah that's because we're looking at [__Relocatable Code__](https://en.wikipedia.org/wiki/Relocation_(computing))!

The __`auipc`__ Offset will be fixed up by the __NuttX ELF Loader__ when it loads our NuttX App for execution.

The __Relocation Info__ shows that __`0x0`__ will be replaced by the Offset of [__puts__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_puts.c#L34-L96)...

```text
printf("Hello, World!!\n");

  ## Load Register RA with Program Counter + 0x0...
  ## But actually 0x0 will be changed to the Offset of puts()
  4a: 00000097  auipc  ra, 0x0  4a: R_RISCV_CALL  puts

  ## Call the function in Register RA: puts()
  ## Which will work when ELF Loader fixes the Offset of puts()
  4e: 000080e7  jalr   ra     # 4a <.LVL1+0x2>
```

So we're all good!

_Why `puts` instead of `printf`?_

The GCC Compiler has cleverly optimised away __printf__ to become __puts__.

If we do this (and foil the GCC Compiler)...

```c
// Nope, GCC Compiler won't change printf() to puts()
printf("Hello, World %s!!\n", "Luppy");
```

Then __printf__ will appear in our RISC-V Disassembly.

Let's circle back to __write__...

![NuttX App calls NuttX Kernel](https://lupyuen.github.io/images/app-run.png)

# NuttX App calls NuttX Kernel

_Our app will print something to the Console Output..._

_But NuttX Apps can't write directly to the Serial Device right?_

Nope! NuttX Apps run in __RISC-V User Mode__. Which doesn't have access to Serial Device and other resources controlled by NuttX Kernel. (Running in __RISC-V Supervisor Mode__)

That's why "__write__" will trigger a __System Call__ to the NuttX Kernel, jumping from RISC-V __User Mode to Supervisor Mode__. And write to the Serial Device.

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
ssize_t write(int parm1, FAR const void * parm2, size_t parm3) {
  return (ssize_t) sys_call3(  // Make a System Call with 3 parameters...
    (unsigned int) SYS_write,  // Kernel Function Number (63 = `write`)
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

It makes a __System Call__ (to NuttX Kernel) with __3 Parameters__: [sys_call3](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/include/syscall.h)

```c
// Make a System Call with 3 parameters
uintptr_t sys_call3(
  unsigned int nbr,  // Kernel Function Number (63 = `write`)
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

[__`ecall`__](https://five-embeddev.com/quickref/instructions.html#-rv32--rv32) is the RISC-V Instruction that triggers a jump from RISC-V __User Mode to Supervisor Mode__. So that NuttX Kernel can execute the actual "__write__" function. (With the actual Serial Device)

(We'll explain how)

_Why the no-op after ecall?_

We're guessing: It might be reserved for special calls to NuttX Kernel in future.

[(Similar to __`ebreak`__ for Semihosting)](https://lupyuen.github.io/articles/semihost#decipher-the-risc-v-exception)

TODO

[Syscall Layer](https://nuttx.apache.org/docs/latest/components/syscall.html)

[syscall.csv](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/syscall/syscall.csv#L209-L210)

[syscall_lookup.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/include/sys/syscall_lookup.h#L202)


List of proxies...

```bash
→ grep PROXY hello.S
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

→ grep PROXY init.S
PROXY__assert.c
PROXY__exit.c
PROXY_clock_gettime.c
PROXY_gettid.c
PROXY_nxsem_wait.c
PROXY_sched_getparam.c
PROXY_sched_setparam.c
PROXY_sem_clockwait.c
PROXY_sem_destroy.c
PROXY_sem_post.c
PROXY_sem_trywait.c
PROXY_task_setcancelstate.c
PROXY_write.c
PROXY_boardctl.c
PROXY_clock_nanosleep.c
PROXY_close.c
PROXY_ftruncate.c
PROXY_get_environ_ptr.c
PROXY_getenv.c
PROXY_gethostname.c
PROXY_ioctl.c
PROXY_kill.c
PROXY_lseek.c
PROXY_lstat.c
PROXY_mkdir.c
PROXY_mount.c
PROXY_nx_pthread_create.c
PROXY_nx_pthread_exit.c
PROXY_nx_vsyslog.c
PROXY_open.c
PROXY_pgalloc.c
PROXY_posix_spawn.c
PROXY_pthread_detach.c
PROXY_read.c
PROXY_rename.c
PROXY_rmdir.c
PROXY_sched_getscheduler.c
PROXY_sched_lock.c
PROXY_sched_unlock.c
PROXY_setenv.c
PROXY_stat.c
PROXY_sysinfo.c
PROXY_umount2.c
PROXY_unlink.c
PROXY_unsetenv.c
PROXY_waitpid.c
```

# NuttX Kernel handles System Call

TODO

From nuttx/syscall/stubs/STUB_write.c

```c
/* Auto-generated write stub file -- do not edit */

#include <nuttx/config.h>
#include <stdint.h>
#include <unistd.h>

uintptr_t STUB_write(int nbr, uintptr_t parm1, uintptr_t parm2, uintptr_t parm3)
{
  return (uintptr_t)write((int)parm1, (FAR const void *)parm2, (size_t)parm3);
}
```

TODO: Handle IRQ 8 (RISCV_IRQ_ECALLU)

[Attach RISCV_IRQ_ECALLU](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_exception.c#L114-L119), which calls...

[riscv_swint](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_swint.c#L105-L537), which calls...

[dispatch_syscall](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_swint.c#L54-L100), which calls Kernel Function Stub and... 

[sys_call2](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/supervisor/riscv_syscall.S#L49-L177) with A0=SYS_syscall_return (3), which calls...

[riscv_perform_syscall](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/supervisor/riscv_perform_syscall.c#L36-L78), which calls...

[riscv_swint](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_swint.c#L105-L537) with IRQ 0, to return from Syscall

From [syscall_lookup.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/include/sys/syscall_lookup.h#L202)

```c
SYSCALL_LOOKUP(write, 3)
```

Which defines SYS_write in the [Syscall Enum](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/include/sys/syscall.h#L55-L66)

From hello.S:

```text
ssize_t write(int parm1, FAR const void * parm2, size_t parm3)
{
 dcc:  872a                  mv  a4,a0

0000000000000dce <.LVL1>:
 dce:  87ae                  mv  a5,a1

0000000000000dd0 <.LVL2>:
 dd0:  86b2                  mv  a3,a2

0000000000000dd2 <.LBB4>:
sys_call3():
/Users/Luppy/ox64/nuttx/include/arch/syscall.h:252
  register long r0 asm("a0") = (long)(nbr);
 dd2:  03f00513            li  a0,63
```

Thus SYS_write = 63

Also from hello.S:

```text
 <2><66e7>: Abbrev Number: 6 (DW_TAG_enumerator)
    <66e8>   DW_AT_name        : (indirect string, offset: 0x4b98): SYS_write
    <66ec>   DW_AT_const_value : 63
```

TODO: Enable CONFIG_DEBUG_SYSCALL_INFO: Build Setup > Debug Options > Syscall Debug Features > Syscall Warning / Error / Info

From [ECALL Log](https://gist.github.com/lupyuen/ce82b29c664b1d5898b6a59743310c17)

```text
riscv_dispatch_irq: irq=8
riscv_swint: Entry: regs: 0x5040bcb0 cmd: 63
up_dump_register: EPC: 00000000800019b2
up_dump_register: A0: 000000000000003f A1: 0000000000000001 A2: 000000008000ad00 A3: 000000000000001e
up_dump_register: A4: 0000000000000001 A5: 000000008000ad00 A6: 0000000000000000 A7: fffffffffffffff8
up_dump_register: T0: 0000000050212a20 T1: 0000000000000007 T2: 0000000000000000 T3: 0000000080200908
up_dump_register: T4: 0000000080200900 T5: 0000000000000000 T6: 0000000000000000
up_dump_register: S0: 00000000802005c0 S1: 0000000080202010 S2: 0000000080202010 S3: 0000000000000000
up_dump_register: S4: 0000000000000001 S5: 0000000000000000 S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 0000000000000000 S9: 0000000000000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 0000000080202b70 FP: 00000000802005c0 TP: 0000000000000000 RA: 0000000080001a6a
riscv_swint: SWInt Return: 37
STUB_write: nbr=440, parm1=1, parm2=8000ad00, parm3=1e

NuttShell (NSH) NuttX-12.0.3
riscv_swint: Entry: regs: 0x5040baa0 cmd: 3
up_dump_register: EPC: 0000000080001a6a
up_dump_register: A0: 0000000000000003 A1: 000000005040bbec A2: 000000000000001e A3: 0000000000000000
up_dump_register: A4: 0000000000007fff A5: 0000000000000001 A6: 0000000000000009 A7: fffffffffffffff8
up_dump_register: T0: 000000000000002e T1: 000000000000006a T2: 00000000000001ff T3: 000000000000006c
up_dump_register: T4: 0000000000000068 T5: 0000000000000009 T6: 000000000000002a
up_dump_register: S0: 00000000802005c0 S1: 0000000080202010 S2: 0000000080202010 S3: 0000000000000000
up_dump_register: S4: 0000000000000001 S5: 0000000000000000 S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 0000000000000000 S9: 0000000000000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 000000005040bcb0 FP: 00000000802005c0 TP: 0000000000000000 RA: 0000000080001a6a
riscv_swint: SWInt Return: 1e
```

Before Call:

A0=0x3f (SYS_write) 

A1=1 (stdout)

A2=0x8000ad00 (g_nshgreeting)

A3=0x1e (length)

nbr=440 (Offset for the stub lookup table, [g_stublookup](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/syscall/syscall_stublookup.c#L80-L93))

After Call:

A0=3 [(SYS_syscall_return)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/include/syscall.h#L80-L87)

Returns 0x1E = 30 chars, including [linefeeds before and after](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/ox64b/nshlib/nsh_parse.c#L292-L302)

Not strictly an SBI like Linux, because the Kernel Function Numbers may change!

But it's a lot simpler to experiment with new Kernel Functions.

# Kernel Accesses User Memory

TODO

Supervisor Mode may access memory in User Mode only if [SUM bit is set in sstatus](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:translation)

[nx_start](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/sched/init/nx_start.c#L298-L713) calls...

[up_initial_state](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_initialstate.c#L41-L140), which calls...

[riscv_set_idleintctx](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_getnewintctx.c#L74-L81) to set the SUM bit in sstatus

# Start NuttX Apps

TODO

NuttX Kernel starts a NuttX App (in ELF Format) by calling...

- [__ELF Loader: g_elfbinfmt__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/binfmt/elf.c#L84-L94), which calls...

- [__elf_loadbinary__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/binfmt/elf.c#L225-L355), which calls...

- [__elf_load__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/binfmt/libelf/libelf_load.c#L297-L445), which calls...

- [__elf_addrenv_alloc__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/binfmt/libelf/libelf_addrenv.c#L56-L178), which calls...

- [__up_addrenv_create__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_addrenv.c#L339-L490), which calls...

  (Also calls [__mmu_satp_reg__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_mmu.h#L152-L176) to set SATP Register)

- [__create_region__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_addrenv.c#L213-L310), which calls...

- [__mmu_ln_setentry__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_mmu.c#L62-L109) to populate the Page Table Entries

_Who calls [ELF Loader g_elfbinfmt](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/binfmt/elf.c#L84-L94) to start the NuttX App?_

Earlier we stepped through the __Boot Sequence__ for NuttX...

- [__"NuttX Boot Flow"__](https://lupyuen.github.io/articles/ox2#appendix-nuttx-boot-flow)

Right after that, [__nx_bringup__](https://github.com/apache/nuttx/blob/master/sched/init/nx_bringup.c#L373-L458) calls...

- [__nx_create_initthread__](https://github.com/apache/nuttx/blob/master/sched/init/nx_bringup.c#L330-L367), which calls...

- [__nx_start_application__](https://github.com/apache/nuttx/blob/master/sched/init/nx_bringup.c#L212C1-L302), which calls...

- [__exec_spawn__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_exec.c#L183-L223), which calls...

- [__exec_internal__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_exec.c#L42-L179), which calls...

- [__load_module__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_loadmodule.c#L136-L225) and...

  [__exec_module__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_execmodule.c#L190-L450)

[__load_module__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_loadmodule.c#L136-L225) calls...

- [__load_absmodule__](https://github.com/apache/nuttx/blob/master/binfmt/binfmt_loadmodule.c#L83-L132), which calls...

- [__binfmt_s.load__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/master/include/nuttx/binfmt/binfmt.h#L122-L148), which calls...

- [__ELF Loader: g_elfbinfmt__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/binfmt/elf.c#L84-L94) to load the ELF File (explained above)

# Initial RAM Disk

TODO

Two ways we can load the Initial RAM Disk...

1.  Load the Initial RAM Disk from a __Separate File: initrd__ (similar to Star64)

    This means we need to modify the [__U-Boot Script: boot-pine64.scr__](https://github.com/openbouffalo/buildroot_bouffalo/blob/main/board/pine64/ox64/boot-pine64.cmd)

    And make it [__load the initrd__](https://lupyuen.github.io/articles/semihost#appendix-boot-nuttx-over-tftp-with-initial-ram-disk) file into RAM.

    (Which is good for separating the NuttX Kernel and NuttX Apps)

    OR...

1.  Append the Initial RAM Disk to the __NuttX Kernel Image__

    So the U-Boot Bootloader will load (one-shot into RAM) the NuttX Kernel + Initial RAM Disk.
    
    And we reuse the existing __U-Boot Config__ on the microSD Card: [__extlinux/extlinux.conf__](https://github.com/openbouffalo/buildroot_bouffalo/blob/main/board/pine64/ox64/rootfs-overlay/boot/extlinux/extlinux.conf)

    (Which might be more efficient for our Limited RAM)

    [(See the __U-Boot Boot Flow__)](https://github.com/openbouffalo/buildroot_bouffalo/wiki/U-Boot-Bootflow)

    __TODO:__ Can we mount the File System directly from the __NuttX Kernel Image in RAM__? Without copying to the [__RAM Disk Memory Region__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L26)?

We'll do the Second Method, since we are low on RAM. Like this...

```bash
## Export the Binary Image to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Insert 64 KB of zeroes after Binary Image for Kernel Stack
head -c 65536 /dev/zero >/tmp/nuttx.zero

## Append Initial RAM Disk to Binary Image
cat nuttx.bin /tmp/nuttx.zero initrd \
  >Image

## Overwrite the Linux Image on Ox64 microSD
cp Image "/Volumes/NO NAME/"
```

This is how we copy the initrd in RAM to the Memory Region for the RAM Disk: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L190-L245)

```c
static void jh7110_copy_ramdisk(void) {
  // Based on ROM FS Format: https://docs.kernel.org/filesystems/romfs.html
  // After _edata, search for "-rom1fs-". This is the RAM Disk Address.
  // Stop searching after 64 KB.
  extern uint8_t _edata[];
  extern uint8_t _sbss[];
  extern uint8_t _ebss[];
  const char *header = "-rom1fs-";
  uint8_t *ramdisk_addr = NULL;
  for (uint8_t *addr = _edata; addr < (uint8_t *)JH7110_IDLESTACK_TOP + (65 * 1024); addr++) {
    if (memcmp(addr, header, strlen(header)) == 0) {
      ramdisk_addr = addr;
      break;
    }
  }
  // Check for Missing RAM Disk
  if (ramdisk_addr == NULL) { _info("Missing RAM Disk"); }
  DEBUGASSERT(ramdisk_addr != NULL); 

  // RAM Disk must be after Idle Stack
  if (ramdisk_addr <= (uint8_t *)JH7110_IDLESTACK_TOP) { _info("RAM Disk must be after Idle Stack"); }
  DEBUGASSERT(ramdisk_addr > (uint8_t *)JH7110_IDLESTACK_TOP);

  // Read the Filesystem Size from the next 4 bytes, in Big Endian
  // Add 0x1F0 to Filesystem Size
  const uint32_t size =
    (ramdisk_addr[8] << 24) + 
    (ramdisk_addr[9] << 16) + 
    (ramdisk_addr[10] << 8) + 
    ramdisk_addr[11] + 
    0x1F0;
  _info("size=%d\n", size);

  // Filesystem Size must be less than RAM Disk Memory Region
  DEBUGASSERT(size <= (size_t)__ramdisk_size);

  // Before Copy: Verify the RAM Disk Image to be copied
  verify_image(ramdisk_addr);

  // Copy the Filesystem Size to RAM Disk Start
  // Warning: __ramdisk_start overlaps with ramdisk_addr + size
  // memmove is aliased to memcpy, so we implement memmove ourselves
  local_memmove((void *)__ramdisk_start, ramdisk_addr, size);

  // Before Copy: Verify the copied RAM Disk Image
  verify_image(__ramdisk_start);
}
```

We copy the initrd at the very top of our NuttX Start Code, before erasing the BSS (in case it corrupts our RAM Disk, but actually it shouldn't): [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L144-L156)

```c
// NuttX Start Code
void jh7110_start(int mhartid) {
  DEBUGASSERT(mhartid == 0); /* Only Hart 0 supported for now */
  if (0 == mhartid) {
    /* Copy the RAM Disk */
    jh7110_copy_ramdisk();

    /* Clear the BSS */
    jh7110_clear_bss();
```

NuttX mounts the RAM Disk from the Memory Region later during startup: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L51-L87)

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

_Why did we insert 64 KB of zeroes after the NuttX Binary Image, before the initrd Initial RAM Disk?_

```bash
## Insert 64 KB of zeroes after Binary Image for Kernel Stack
head -c 65536 /dev/zero >/tmp/nuttx.zero

## Append Initial RAM Disk to Binary Image
cat nuttx.bin /tmp/nuttx.zero initrd \
  >Image
```

When we refer to the [NuttX Log](https://gist.github.com/lupyuen/74a44a3e432e159c62cc2df6a726cb89) and the [NuttX Linker Script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script)...

```text
// End of Data Section
_edata=0x50400258

// Start of BSS Section
_sbss=0x50400290

// End of BSS Section
_ebss=0x50407000

// Top of Idle Stack
JH7110_IDLESTACK_TOP=0x50407c00

// We located the initd after the Top of Idle Stack
ramdisk_addr=0x50408288, size=8192016

// And we copied initrd to the Memory Region for the RAM Disk
__ramdisk_start=0x50a00000
```

Which says...

1.  The NuttX Binary Image `nuttx.bin` terminates at `_edata`. (End of Data Section)

1.  If we append `initrd` directly to the end of `nuttx.bin`, it will collide with the [BSS Section](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L74-L92) and the [Idle Stack](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_head.S#L94-L101). And `initrd` will get overwritten by NuttX.

1.  Best place to append `initrd` is after the Top of Idle Stack. Which is located 32 KB after `_edata`. (End of Data Section)

1.  That's why we inserted a padding of 64 KB between `nuttx.bin` and `initrd`. So it won't collide with BSS and Idle Stack.

1.  Our code locates `initrd` (searching by Magic Number "-rom1fs-"). And copies `initrd` to `__ramdisk_start`. (Memory Region for the RAM Disk)

1.  NuttX mounts the RAM Disk from `__ramdisk_start`. (Memory Region for the RAM Disk)

_But 64 KB sounds so arbitrary. What if the parameters change?_

That's why we have a Runtime Check: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L190-L245)

```c
  // RAM Disk must be after Idle Stack
  if (ramdisk_addr <= (uint8_t *)JH7110_IDLESTACK_TOP) { _info("RAM Disk must be after Idle Stack"); }
  DEBUGASSERT(ramdisk_addr > (uint8_t *)JH7110_IDLESTACK_TOP);
```

_Why did we call local_memmove to copy `initrd` to `__ramdisk_start`? Why not memcpy?_

That's because `initrd` overlaps with `__ramdisk_start`!

```
ramdisk_addr = 0x50408288, size = 8192016
ramdisk_addr + size = 0x50bd8298
Which is AFTER __ramdisk_start (0x50a00000)
```

`memcpy` won't work with Overlapping Memory Regions. So we wrote our own: [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L246-L487)

```c
// From libs/libc/string/lib_memmove.c
static FAR void *local_memmove(FAR void *dest, FAR const void *src, size_t count) {
  FAR char *d;
  FAR char *s;
  DEBUGASSERT(dest > src);
  d = (FAR char *) dest + count;
  s = (FAR char *) src + count;

  while (count--) {
    d -= 1;
    s -= 1;
    // TODO: Very strange. This needs to be volatile or C Compiler will replace this by memcpy.
    volatile char c = *s;
    *d = c;
  }
  return dest;
}
```

_We're sure that it works?_

That's why we called `verify_image` to do a simple integrity check on `initrd`, before and after copying. And that's how we discovered that `memcpy` doesn't work. From [jh7110_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_start.c#L246-L487)

```c
// Verify that image is correct
static void verify_image(uint8_t *addr) {
  // Verify that the Byte Positions below (offset by 1) contain 0x0A
  for (int i = 0; i < sizeof(search_addr) / sizeof(search_addr[0]); i++) {
    const uint8_t *p = addr + search_addr[i] - 1;
    if (*p != 0x0A) { _info("No Match: %p\n", p); }
  }
}

// Byte Positions (offset by 1) of 0x0A in initrd. Extracted from:
// grep --binary-files=text -b -o A initrd
const uint32_t search_addr[] =
{
76654,
78005,
79250,
...
7988897,
7992714,
};
```

But NuttX fails to start our NuttX Shell (NSH) ELF Executable from "/system/bin/init"...

```text
elf_read: Read 3392 bytes from offset 3385080
elf_addrenv_select: ERROR: up_addrenv_text_enable_write failed: -22
elf_load: ERROR: elf_addrenv_select() failed: -22
...
elf_loadbinary: Failed to load ELF program binary: -22
exec_internal: ERROR: Failed to load program '/system/bin/init': -22
_assert: Current Version: NuttX  12.0.3 8017bd9-dirty Nov 10 2023 22:50:07 risc-v
_assert: Assertion failed ret > 0: at file: init/nx_bringup.c:302 task: AppBringUp process: Kernel 0x502014ea
```

[(Source)](https://gist.github.com/lupyuen/74a44a3e432e159c62cc2df6a726cb89)

Maybe because NuttX is trying to map the User Address Space 0xC000 0000: [nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L17-L26)

```text
CONFIG_ARCH_TEXT_VBASE=0xC0000000
CONFIG_ARCH_TEXT_NPAGES=128
CONFIG_ARCH_DATA_VBASE=0xC0100000
CONFIG_ARCH_DATA_NPAGES=128
CONFIG_ARCH_HEAP_VBASE=0xC0200000
CONFIG_ARCH_HEAP_NPAGES=128
```

But our Kernel Memory Space already extends to 0xF000 0000? (Because of the PLIC at 0xE000 0000)

From [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L43-L46):

```c
/* Map the whole I/O memory with vaddr = paddr mappings */
#define MMU_IO_BASE     (0x00000000)
#define MMU_IO_SIZE     (0xf0000000)
```

_Let's disable PLIC, and exclude PLIC from Memory Map. Will the NuttX Shell start?_

Yep it does! [(See the log)](https://gist.github.com/lupyuen/9fc9b2de9938b48666cc5e5fa3f8278e)

![Ox64 boots to NuttX Shell](https://lupyuen.github.io/images/mmu-boot1.png)

[_Ox64 boots to NuttX Shell_](https://gist.github.com/lupyuen/aa9b3e575ba4e0c233ab02c328221525)

# What's Next

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
