# RISC-V Ox64 BL808 SBC: NuttX Apps and Initial RAM Disk

📝 _30 Nov 2023_

![TODO](https://lupyuen.github.io/images/app-title.png)

TODO

[__Pine64 Ox64 64-bit RISC-V SBC__](https://wiki.pine64.org/wiki/Ox64). (Pic below)

(Powered by [__Bouffalo Lab BL808 SoC__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf))

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2). (Real-Time Operating System)

![Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)](https://lupyuen.github.io/images/ox64-solder.jpg)

[_Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)_](https://wiki.pine64.org/wiki/Ox64)

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

# Inside a NuttX App

TODO

_What's inside the simplest app for NuttX?_

From [hello_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/ox64b/examples/hello/hello_main.c#L36-L40)

```c
int main(int argc, FAR char *argv[]) {
  printf("Hello, World!!\n");
  return 0;
}
```

Here's the RISC-V Disassembly: [hello.S](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/ox64a-1/hello.S)

```text
000000000000003e <main>:
main():
apps/examples/hello/hello_main.c:37
/****************************************************************************
 * hello_main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  3e:	1141                	addi	sp,sp,-16
apps/examples/hello/hello_main.c:38
  printf("Hello, World!!\n");
  40:	00000517          	auipc	a0,0x0	40: R_RISCV_PCREL_HI20	.LC0
	40: R_RISCV_RELAX	*ABS*
  44:	00050513          	mv	a0,a0	44: R_RISCV_PCREL_LO12_I	.L0 
	44: R_RISCV_RELAX	*ABS*

0000000000000048 <.LVL1>:
apps/examples/hello/hello_main.c:37
{
  48:	e406                	sd	ra,8(sp)
apps/examples/hello/hello_main.c:38
  printf("Hello, World!!\n");
  4a:	00000097          	auipc	ra,0x0	4a: R_RISCV_CALL	puts
	4a: R_RISCV_RELAX	*ABS*
  4e:	000080e7          	jalr	ra # 4a <.LVL1+0x2>

0000000000000052 <.LVL2>:
apps/examples/hello/hello_main.c:40
  return 0;
}
  52:	60a2                	ld	ra,8(sp)
  54:	4501                	li	a0,0
  56:	0141                	addi	sp,sp,16
  58:	8082                	ret
```

We see that [main](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/ox64b/examples/hello/hello_main.c#L36-L40) calls...

- [puts](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_puts.c#L34-L96), which calls...

- [lib_fwrite_unlocked](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_libfwrite.c#L45-L200), which calls...

- [stream->fs_iofunc.write](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_libfwrite.c#L145) OR...

  [write](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/libs/libc/stdio/lib_libfwrite.c#L149) (See below)

TODO: Which one?

TODO: _start prepares sig_trampoline and calls main

_This code doesn't look right..._

```text
apps/examples/hello/hello_main.c:38
  printf("Hello, World!!\n");
  4a:	00000097          	auipc	ra,0x0
  4e:	000080e7          	jalr	ra
```

That's because this is __Relocatable Code__. The auipc offset will be fixed up by the NuttX ELF Loader when it loads this code into User Memory.

The Relocation Info shows that 0x0 will be replaced by the address of `puts`...

```text
  4a:	00000097          	auipc	ra,0x0
  4a: R_RISCV_CALL	puts
  4e:	000080e7          	jalr	ra
```

_Why `puts` instead of `printf`?_

The GCC Compiler has cleverly optimised away `printf` to become `puts`.

If we do this...

```c
  printf("Hello, World %s!!\n", "Luppy");
```

Then `printf` will appear in our disassembly.

# NuttX App calls NuttX Kernel

TODO

[Syscall Layer](https://nuttx.apache.org/docs/latest/components/syscall.html)

[syscall.csv](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/syscall/syscall.csv#L209-L210)

[syscall_lookup.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/include/sys/syscall_lookup.h#L202)

Our NuttX App calls `write`, which is a Proxy Version...

From nuttx/syscall/proxies/PROXY_write.c

```c
/* Auto-generated write proxy file -- do not edit */

#include <nuttx/config.h>
#include <unistd.h>
#include <syscall.h>

ssize_t write(int parm1, FAR const void * parm2, size_t parm3)
{
  return (ssize_t)sys_call3((unsigned int)SYS_write, (uintptr_t)parm1, (uintptr_t)parm2, (uintptr_t)parm3);
}
```
Proxy for `write` calls...

[sys_call3](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/include/syscall.h), which makes an `ecall` to NuttX Kernel...

```c
static inline uintptr_t sys_call3(unsigned int nbr, uintptr_t parm1,
                                  uintptr_t parm2, uintptr_t parm3)
{
  register long r0 asm("a0") = (long)(nbr);
  register long r1 asm("a1") = (long)(parm1);
  register long r2 asm("a2") = (long)(parm2);
  register long r3 asm("a3") = (long)(parm3);

  asm volatile
    (
     "ecall"
     :: "r"(r0), "r"(r1), "r"(r2), "r"(r3)
     : "memory"
     );

  asm volatile("nop" : "=r"(r0));

  return r0;
}
```

TODO: Why `nop`?

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

# Kernel Handles App Call

TODO

nuttx/syscall/stubs/STUB_write.c

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

[dispatch_syscall](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_swint.c#L54-L100), which calls...

[sys_call2](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/supervisor/riscv_syscall.S#L49-L177), which calls...

[riscv_perform_syscall](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/supervisor/riscv_perform_syscall.c#L36-L78), which calls...

[riscv_swint](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64b/arch/risc-v/src/common/riscv_swint.c#L105-L537) with IRQ 0, which calls...

???

From apps/import/include/sys/syscall_lookup.h

```c
SYSCALL_LOOKUP(write,                      3)
```

From hello.S

```text
ssize_t write(int parm1, FAR const void * parm2, size_t parm3)
{
 dcc:	872a                	mv	a4,a0

0000000000000dce <.LVL1>:
 dce:	87ae                	mv	a5,a1

0000000000000dd0 <.LVL2>:
 dd0:	86b2                	mv	a3,a2

0000000000000dd2 <.LBB4>:
sys_call3():
/Users/Luppy/ox64/nuttx/include/arch/syscall.h:252
  register long r0 asm("a0") = (long)(nbr);
 dd2:	03f00513          	li	a0,63
```

Thus SYS_write = 63

TODO: Enable CONFIG_DEBUG_SYSCALL_INFO: Build Setup > Debug Options > Syscall Debug Features > Syscall Warning / Error / Info

# Kernel Accesses User Memory

TODO

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
