# RISC-V Star64 JH7110: Power Up the Display Controller with U-Boot Bootloader

📝 _7 Sep 2023_

![Star64 JH7110 Display Controller is alive!](https://lupyuen.github.io/images/display3-title.png)

In the olden days we would __`peek`__ and __`poke`__ the __Display Controller__, to see weird and wonderful displays.

Today (46 years later), we poke around the Display Controller of [__Star64 JH7110 RISC-V SBC__](https://wiki.pine64.org/wiki/STAR64) with a modern tool (not BASIC): [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64)!

(Spoiler: No weird and wonderful displays for today!)

In this article we discover...

- U-Boot Commands __`md`__ and __`mw`__  for Dumping and Writing Memory (Pic above)

- Which we use to power up the __Video Output__ and __Display Controller__ on the [__RISC-V StarFive JH7110 SoC__](https://doc-en.rvspace.org/Doc_Center/jh7110.html)

- By tweaking the JH7110 Registers for __Power Management Unit__, __Clock and Reset__

- And how we'll create our own __Display Driver__ for JH7110

- In spite of the __Missing and Incorrect Docs__

_Why are we doing this?_

We're building a __HDMI Display Driver__ for [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/release) (RTOS) on the Star64 SBC. (And probably for VisionFive2 too)

Our analysis today will be super useful for creating our __HDMI Driver for NuttX__ on Star64. (Pic below)

And hopefully this article will be helpful for __porting other Operating Systems__ to JH7110!

![Pine64 Star64 RISC-V SBC](https://lupyuen.github.io/images/linux-title.jpg)

# Dump and Write Memory with U-Boot Bootloader

_Our Bootloader will Read AND Write any Memory?_

Yep! Inside our Star64 SBC is the powerful (maybe risky) [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64) that will read and write JH7110 SoC's Memory: __RAM, ROM, even I/O Registers__!

(ROM is read-only of course)

Boot Star64 __without a microSD Card__ and shut down our [__TFTP Server__](https://lupyuen.github.io/articles/tftp). We should see the __U-Boot Prompt__.

The __`md`__ command will dump JH7110 Memory (RAM, ROM, I/O Registers)...

```text
# md
md - memory display
Usage: md [.b, .w, .l, .q] address [# of objects]
```

Let's dump the __JH7110 Boot ROM__ at [__`0x2A00` `0000`__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/system_memory_map.html)...

```text
# md 2A000000 0x20
2a000000: 00000297 12628293 30529073 30005073  ......b.s.R0sP.0
2a000010: 30405073 41014081 42014181 43014281  sP@0.@.A.A.B.B.C
2a000020: 44014381 45014481 46014581 47014681  .C.D.D.E.E.F.F.G
2a000030: 48014781 49014881 4a014981 4b014a81  .G.H.H.I.I.J.J.K
2a000040: 4c014b81 4d014c81 4e014d81 4f014e81  .K.L.L.M.M.N.N.O
2a000050: 01974f81 8193d710 02970ae1 82930000  .O..............
```

(Cute Alphabet Soup. Wonder where's the Source Code?)

_This works for I/O Registers?_

We can dump the __JH7110 UART Registers__ at [__`0x1000` `0000`__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/system_memory_map.html)...

```text
# md 10000000 0x20
10000000: 0000006d 00000000 000000c1 00000003  m...............
10000010: 00000003 00000000 00000000 00000000  ................
10000020: 00000000 00000000 00000000 00000000  ................
10000030: 00000064 00000064 00000064 00000064  d...d...d...d...
```

_What about writing to I/O Registers?_

Let's __write to UART Registers__. The __`mw`__ command writes to JH7110 Memory...

```text
# mw
mw - memory write (fill)
Usage: mw [.b, .w, .l, .q] address value [count]
```

(Hmmm sounds like a Security Risk)

To transmit some UART Output, we poke `0x2A` into the __UART Transmit Register__ at [__`0x1000` `0000`__](https://lupyuen.github.io/articles/nuttx2#uart-controller-on-star64)...

```text
# mw 10000000 2a 1
*
```

Yep it prints "__`*`__", which is ASCII Code 2A!

Let's do something more sophisticated: JH7110 Display Controller...

# Dump the JH7110 Display Controller

_Dumping the JH7110 Display Controller should work right?_

Let's find out! Based on...

- [__JH7110 Display Subsystem Memory Map__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/memory_map_display.html)

- [__JH7110 System Memory Map__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/system_memory_map.html)

The registers for __JH7110 Display Subsystem__ are at...

| Address | Display Registers |
|:-------:|:------------------|
| __`0x2940 0000`__ | __DC8200 AHB0__ _(Display Bus 0)_
| __`0x2948 0000`__ | __DC8200 AHB1__ _(Display Bus 1)_
| __`0x2959 0000`__ | __U0_HDMITX__ _(HDMI)_
| __`0x295B 0000`__ | __VOUT_SYSCON__ _(System Config)_
| __`0x295C 0000`__ | __VOUT_CRG__ _(Clock and Reset)_
| __`0x295D 0000`__ | __DSI TX__ _(MIPI Display Serial Interface)_
| __`0x295E 0000`__ | __MIPITX DPHY__ _(MIPI Display Physical Layer)_

[(__DC8200__ is the __VeriSilicon Dual Display Controller__)](https://lupyuen.github.io/articles/display2#dc8200-display-controller)

Let's dump the above __Display Subsystem Registers__...

```text
# md 29400000 0x20
29400000: 00000000 00000000 00000000 00000000  ................
29400010: 00000000 00000000 00000000 00000000  ................

# md 29480000 0x20
29480000: 00000000 00000000 00000000 00000000  ................
29480010: 00000000 00000000 00000000 00000000  ................

# md 29590000 0x20
29590000: 00000000 00000000 00000000 00000000  ................
29590010: 00000000 00000000 00000000 00000000  ................

# md 295B0000 0x20
295b0000: 00000000 00000000 00000000 00000000  ................
295b0010: 00000000 00000000 00000000 00000000  ................

# md 295C0000 0x20
295c0000: 00000000 00000000 00000000 00000000  ................
295c0010: 00000000 00000000 00000000 00000000  ................
```

_But the values are all zero!_

That's because the Display Subsystem is __not powered up__.

Let's tweak some registers and power up the Display Subsystem...

![JH7110 Display Subsystem Block Diagram](https://lupyuen.github.io/images/display2-vout_block_diagram18.png)

[_JH7110 Display Subsystem Block Diagram_](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/block_diagram_display.html)

# JH7110 Power Management Unit

_How will we power up the Display Subsystem?_

From the pic above, the Display Subsystem is powered in the __Video Output Power Domain (DOM_VOUT)__.

Which is powered by the JH7110 [__Power Management Unit__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/overview_pm.html) (PMU or PMIC)...

![Power Management Unit](https://doc-en.rvspace.org/JH7110/TRM/Image/RD/JH7110/power_stratey.png)

[(Source)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/overview_pm.html)

_Is the power turned on for Video Output DOM_VOUT?_

Let's dump the status of the Power Domains...

- From [__System Memory Map__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/system_memory_map.html): Base Address of PMU is __`0x1703` `0000`__

- From [__PMU Registers__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/register_info_pmu.html#register_info_pmu__section_rcx_pqz_msb): Current Power Mode is at Offset __`0x80`__

Which means the __Current Power Mode__ is at __`0x1703` `0080`__. Let's dump the register...

```text
# md 17030080 1
17030080: 00000003
```

[__Current Power Mode__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/register_info_pmu.html#register_info_pmu__section_rcx_pqz_msb) is 3, which says that...

- __SYSTOP Power__ (Bit 0) is On
- __CPU Power__ (Bit 1) is On
- But __VOUT Power__ (Bit 4) is Off!

_So how to power up VOUT?_

From the [__PMU Function Description__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/function_descript_pmu.html)...

> __SW Encourage Turn-on Sequence__

> (1) Configure the register __SW Turn-On Power Mode__ (offset __`0x0C`__), write the bit 1 which Power Domain will be turn-on, write the others 0;

> (2) Write the __SW Turn-On Command Sequence__. Write the register Software Encourage (offset __`0x44`__) __`0xFF`__ → __`0x05`__ → __`0x50`__

_What's a "Software Encourage"?_

Something got Lost in Translation. Let's assume it means "Software Trigger".

Which means we set the [__Power Mode__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/register_info_pmu.html#register_info_pmu__section_nhb_slz_msb) (Offset __`0x0C`__) to __`0x10`__ (Bit 4 for VOUT)...

```text
# mw 1703000c 0x10 1
```

Then we write the [__Command Sequence__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/register_info_pmu.html#register_info_pmu__section_jdh_x4z_msb) at Offset __`0x44`__ (no delays needed)...

```text
# mw 17030044 0xff 1
# mw 17030044 0x05 1
# mw 17030044 0x50 1
```

Finally we dump the [__Current Power Mode__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/register_info_pmu.html#register_info_pmu__section_rcx_pqz_msb)...

```text
# md 17030080 1
17030080: 00000013
```

__Video Output Power VOUT__ (Bit 4) is now on!

_So we can dump the Display Subsystem now?_

Sadly nope, the __Display Subsystem Registers__ are still empty...

```text
# md 295C0000 0x20
295c0000: 00000000 00000000 00000000 00000000  ................
295c0010: 00000000 00000000 00000000 00000000  ................
```

We need more tweaks, for the Clock and Reset Signals...

TODO: Pic of JH7110 Clock Structure

[_JH7110 Clock Structure_](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/clock_structure.html)

# Clocks and Reset for Display Subsystem

_Display Subsystem (VOUT) is already powered up via the Power Management Unit (PMU)..._

_Anything else we need to make it work?_

Always remember to enable the __Clocks__ and deassert the __Resets__!

According to the [__JH7110 Clock Structure__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/clock_structure.html) (pic above), the __Display Subsystem (VOUT)__ is Clocked by...

- __clk_vout_root__
- __mipiphy ref clk__
- __hdmiphy ref clk__
- __clk_vout_src__ (1228.8 MHz)
- __clk_vout_axi__ (614.4 MHz)
- __clk_vout_ahb__ (204.8 MHz) / __clk_ahb1__
- __clk_mclk__ (51.2 MHz)

Plus one Reset...

- __rstn_vout__

_How to enable the Clocks and deassert the Resets?_

We'll set the [__System Control Registers (SYS CRG)__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/sys_crg.html) at Base Address __`0x1302` `0000`__

[(From the __System Memory Map__)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/system_memory_map.html)

When we match the above Clocks to the [__System Control Registers (SYS CRG)__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/sys_crg.html), we get...

| SYS CRG Offset | Clock |
|:--------------:|:------|
| __`0x28`__ | Clock AHB 1
| __`0x4C`__ | MCLK Out  
| __`0x98`__ | clk_u0_sft7110_noc_bus_clk_cpu_axi  
| __`0x9C`__ | clk_u0_sft7110_noc_bus_clk_axicfg0_axi  
| __`0xE8`__ | clk_u0_dom_vout_top_clk_dom_vout_top_clk_vout_src  
| __`0xF0`__ | Clock NOC Display AXI  
| __`0xF4`__ | Clock Video Output AHB  
| __`0xF8`__ | Clock Video Output AXI  
| __`0xFC`__ | Clock Video Output HDMI TX0 MCLK  

(Looks excessive, but better to enable more Clocks than too few!)

To enable the Clock Registers above, we set __Bit 31 (clk_icg)__ to 1.

Here are the U-Boot Commands to enable the Clocks...

```text
mw 13020028 0x80000000 1
mw 1302004c 0x80000000 1
mw 13020098 0x80000000 1
mw 1302009c 0x80000000 1
mw 130200e8 0x80000000 1
mw 130200f0 0x80000000 1
mw 130200f4 0x80000000 1
mw 130200f8 0x80000000 1
mw 130200fc 0x80000000 1
```

_What about the Resets?_

Looking up the [__System Control Registers (SYS CRG)__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/sys_crg.html), we need to __deassert these Resets__...

- __Software RESET 1 Address Selector__ (SYS CRG Offset __`0x2FC`__)

  __Bit 11:__ rstn_u0_dom_vout_top_rstn_dom_vout_top_rstn_vout_src

- __SYSCRG RESET Status 0__ (SYS CRG Offset __`0x308`__)

  __Bit 26:__ rstn_u0_sft7110_noc_bus_reset_disp_axi_n

- __SYSCRG RESET Status 1__ (SYS CRG Offset __`0x30C`__)

  __Bit 11:__ rstn_u0_dom_vout_top_rstn_dom_vout_top_rstn_vout_src

We set the above bits to 0 to deassert the Resets.

First we dump the above __Reset Registers__...

```text
# md 130202fc 1
130202fc: 07e7fe00

# md 13020308 1
13020308: ff9fffff

# md 1302030c 1
1302030c: f80001ff
```

Then we flip the __Reset Bits__...

```text
# mw 130202fc 0x07e7f600 1
# mw 13020308 0xfb9fffff 1
```

(The last Reset is already deasserted, no need to change it)

_What happens when we enable the Clocks and deassert the Resets?_

We run the above commands to set the Clocks and Resets.

And again we dump the __Display Subsystem Registers__...

```text
# md 295C0000 0x20
295c0000: 00000004 00000004 00000004 0000000c  ................
295c0010: 00000000 00000000 00000000 00000000  ................
295c0020: 00000000 00000000 00000000 00000000  ................
295c0030: 00000000 00000000 00000000 00000000  ................
295c0040: 00000000 00000000 00000fff 00000000  ................
```

The Display Systems Registers are now visible at VOUT CRG __`0x295C` `0000`__...

Which means the Display Subsystem is alive yay!

![Star64 JH7110 Display Subsystem is alive!](https://lupyuen.github.io/images/display3-title.png)

TODO: The Default Values seem to match [DOM VOUT CRG](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/dom_vout_crg.html). (`clk_tx_esc` should have default `24'hc`, there is a typo in the doc: `24'h12`)

![`clk_tx_esc` should have default `24'hc`, there is a typo in the doc: `24'h12`](https://lupyuen.github.io/images/display3-typo.png)

# U-Boot Script to Power Up Display Subsystem

TODO

_That's a long list of U-Boot Commands. Can we automate this?_

```text
mw 1703000c 0x10 1
mw 17030044 0xff 1
mw 17030044 0x05 1
mw 17030044 0x50 1
mw 13020028 0x80000000 1
mw 1302004c 0x80000000 1
mw 13020098 0x80000000 1
mw 1302009c 0x80000000 1
mw 130200e8 0x80000000 1
mw 130200f0 0x80000000 1
mw 130200f4 0x80000000 1
mw 130200f8 0x80000000 1
mw 130200fc 0x80000000 1
mw 130202fc 0x7e7f600 1
mw 13020308 0xfb9fffff 1
md 295C0000 0x20
```

Sure can! Run this in U-Boot...

```text
## Create the command to power up the Video Output
setenv video_on 'mw 1703000c 0x10 1 ; mw 17030044 0xff 1 ; mw 17030044 0x05 1 ; mw 17030044 0x50 1 ; mw 13020028 0x80000000 1 ; mw 1302004c 0x80000000 1 ; mw 13020098 0x80000000 1 ; mw 1302009c 0x80000000 1 ; mw 130200e8 0x80000000 1 ; mw 130200f0 0x80000000 1 ; mw 130200f4 0x80000000 1 ; mw 130200f8 0x80000000 1 ; mw 130200fc 0x80000000 1 ; mw 130202fc 0x7e7f600 1 ; mw 13020308 0xfb9fffff 1 ; md 295C0000 0x20 ; '

## Check that it's correct
printenv video_on

## Save it for future reboots
saveenv

## Run the command to power up the Video Output
run video_on
```

(The `run` feels a bit like BASIC)

We should see...

```text
StarFive # run video_on
295c0000: 00000004 00000004 00000004 0000000c  ................
295c0010: 00000000 00000000 00000000 00000000  ................
295c0020: 00000000 00000000 00000000 00000000  ................
295c0030: 00000000 00000000 00000000 00000000  ................
295c0040: 00000000 00000000 00000fff 00000000  ................
295c0050: 00000000 00000000 00000000 00000000  ................
295c0060: 00000000 00000000 00000000 00000000  ................
295c0070: 00000000 00000000 00000000 00000000  ................
```

So much easier!

Maybe we could use this to render something to the HDMI Display!

(Before converting to C for NuttX)

_How will we test this in NuttX?_

Probably inside `board_late_initialize` like this: [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/hdmi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L154-L215)

```c
void board_late_initialize(void) {
  /* Mount the RAM Disk */
  mount_ramdisk();

  /* Perform board-specific initialization */
#ifdef CONFIG_NSH_ARCHINIT
  mount(NULL, "/proc", "procfs", 0, NULL);
#endif

  // Verfy that Display Controller is down
  uint32_t val = getreg32(0x295C0000);
  DEBUGASSERT(val == 0);

  // Power up the Display Controller
  // TODO: Switch to constants
  putreg32(0x10, 0x1703000c);
  putreg32(0xff, 0x17030044);
  putreg32(0x05, 0x17030044);
  putreg32(0x50, 0x17030044);
  putreg32(0x80000000, 0x13020028);
  putreg32(0x80000000, 0x1302004c);
  putreg32(0x80000000, 0x13020098);
  putreg32(0x80000000, 0x1302009c);
  putreg32(0x80000000, 0x130200e8);
  putreg32(0x80000000, 0x130200f0);
  putreg32(0x80000000, 0x130200f4);
  putreg32(0x80000000, 0x130200f8);
  putreg32(0x80000000, 0x130200fc);

  // Software RESET 1 Address Selector: Offset 0x2fc
  // Clear Bit 11: rstn_u0_dom_vout_top_rstn_dom_vout_top_rstn_vout_src
  modifyreg32(0x130202fc, 1 << 11, 0);  // Addr, Clear Bits, Set Bits

  // SYSCRG RESET Status 0: Offset 0x308
  // Clear Bit 26: rstn_u0_sft7110_noc_bus_reset_disp_axi_n
  modifyreg32(0x13020308, 1 << 26, 0);  // Addr, Clear Bits, Set Bits

  // Verfy that Display Controller is up
  val = getreg32(0x295C0000);
  DEBUGASSERT(val == 4);

  // Test HDMI
  int test_hdmi(void);
  int ret = test_hdmi();
  DEBUGASSERT(ret == 0);
}

// Display Subsystem Base Address
// https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/memory_map_display.html
#define DISPLAY_BASE_ADDRESS (0x29400000)

// DOM VOUT Control Registers
// https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/memory_map_display.html
#define CRG_BASE_ADDRESS     (DISPLAY_BASE_ADDRESS + 0x1C0000)

// Enable Clock
// https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/dom_vout_crg.html
#define CLK_ICG (1 << 31)

// https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/dom_vout_crg.html
#define clk_u0_dc8200_clk_pix0 (CRG_BASE_ADDRESS + 0x1c)

// Test HDMI
int test_hdmi(void) { ... }
```

# Read the Star64 JH7110 Display Controller Registers with U-Boot Bootloader

TODO

From [jh7110_appinit.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/hdmi/boards/risc-v/jh7110/star64/src/jh7110_appinit.c#L154-L215):

```c
// Display Subsystem Base Address
// https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/memory_map_display.html
#define DISPLAY_BASE_ADDRESS (0x29400000)

// DOM VOUT Control Registers
// https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/memory_map_display.html
#define CRG_BASE_ADDRESS     (DISPLAY_BASE_ADDRESS + 0x1C0000)

// DOM VOUT Control Registers
// https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/dom_vout_crg.html

#define clk_u0_dc8200_clk_axi   (CRG_BASE_ADDRESS + 0x10)
#define clk_u0_dc8200_clk_core  (CRG_BASE_ADDRESS + 0x14)
#define clk_u0_dc8200_clk_ahb   (CRG_BASE_ADDRESS + 0x18)
#define clk_u0_dc8200_clk_pix0  (CRG_BASE_ADDRESS + 0x1c)
#define clk_u0_dc8200_clk_pix1  (CRG_BASE_ADDRESS + 0x20)
#define clk_u0_hdmi_tx_clk_mclk (CRG_BASE_ADDRESS + 0x3c)
#define clk_u0_hdmi_tx_clk_bclk (CRG_BASE_ADDRESS + 0x40)
#define clk_u0_hdmi_tx_clk_sys  (CRG_BASE_ADDRESS + 0x44)
#define CLK_ICG (1 << 31)

#define Software_RESET_assert0_addr_assert_sel (CRG_BASE_ADDRESS + 0x38)
#define rstn_u0_dc8200_rstn_axi   (1 << 0)
#define rstn_u0_dc8200_rstn_ahb   (1 << 1)
#define rstn_u0_dc8200_rstn_core  (1 << 2)
#define rstn_u0_hdmi_tx_rstn_hdmi (1 << 9)
```

U-Boot Commands:

```text
run video_on
mw 295C0010 0x80000000 1
mw 295C0014 0x80000000 1
mw 295C0018 0x80000000 1
mw 295C001c 0x80000000 1
mw 295C0020 0x80000000 1
mw 295C003c 0x80000000 1
mw 295C0040 0x80000000 1
mw 295C0044 0x80000000 1

md 295C0038 1
mw 295C0038 0 1
md 295C0038 1

md 295C004c 1
mw 295C004c 0 1
md 295C004c 1

## TODO: Why is Reset at 295C0048?
md 295C0048 1
mw 295C0048 0 1
md 295C0048 1

md 29400000 0x20
md 29480000 0x20
md 295C0000 0x20
```

U-Boot Log:

```text
StarFive # run video_on
295c0000: 00000004 00000004 00000004 0000000c  ................
295c0010: 00000000 00000000 00000000 00000000  ................
295c0020: 00000000 00000000 00000000 00000000  ................
295c0030: 00000000 00000000 00000000 00000000  ................
295c0040: 00000000 00000000 00000fff 00000000  ................
295c0050: 00000000 00000000 00000000 00000000  ................
295c0060: 00000000 00000000 00000000 00000000  ................
295c0070: 00000000 00000000 00000000 00000000  ................
StarFive # mw 295C0010 0x80000000 1
StarFive # 
StarFive # mw 295C0014 0x80000000 1
StarFive # 
StarFive # mw 295C0018 0x80000000 1
StarFive # 
StarFive # mw 295C001c 0x80000000 1
StarFive # 
StarFive # mw 295C0020 0x80000000 1
StarFive # 
StarFive # mw 295C003c 0x80000000 1
StarFive # 
StarFive # mw 295C0040 0x80000000 1
StarFive # 
StarFive # mw 295C0044 0x80000000 1
StarFive # 
StarFive # md 29400000 0x20
29400000: 00000000 00000000 00000000 00000000  ................
29400010: 00000000 00000000 00000000 00000000  ................
29400020: 00000000 00000000 00000000 00000000  ................
29400030: 00000000 00000000 00000000 00000000  ................
29400040: 00000000 00000000 00000000 00000000  ................
29400050: 00000000 00000000 00000000 00000000  ................
29400060: 00000000 00000000 00000000 00000000  ................
29400070: 00000000 00000000 00000000 00000000  ................
StarFive # mw 295C0038 0 1
StarFive # 
StarFive # md 29400000 0x20
29400000: 00000000 00000000 00000000 00000000  ................
29400010: 00000000 00000000 00000000 00000000  ................
29400020: 00000000 00000000 00000000 00000000  ................
29400030: 00000000 00000000 00000000 00000000  ................
29400040: 00000000 00000000 00000000 00000000  ................
29400050: 00000000 00000000 00000000 00000000  ................
29400060: 00000000 00000000 00000000 00000000  ................
29400070: 00000000 00000000 00000000 00000000  ................
StarFive # mw 295C004c 0 1
StarFive # 
StarFive # md 29400000 0x20
29400000: 00000000 00000000 00000000 00000000  ................
29400010: 00000000 00000000 00000000 00000000  ................
29400020: 00000000 00000000 00000000 00000000  ................
29400030: 00000000 00000000 00000000 00000000  ................
29400040: 00000000 00000000 00000000 00000000  ................
29400050: 00000000 00000000 00000000 00000000  ................
29400060: 00000000 00000000 00000000 00000000  ................
29400070: 00000000 00000000 00000000 00000000  ................
StarFive # mw 295C0048 0 1
StarFive # 
StarFive # md 29400000 0x20
29400000: 00000900 80010000 00222200 00000000  ........."".....
29400010: 00000000 00000004 14010000 000b4b41  ............AK..
29400020: 00008200 00005720 20210316 16015600  .... W....! .V..
29400030: 0000030e a0600084 00000000 00000000  ......`.........
29400040: 00000000 00000000 00000000 00000000  ................
29400050: 00000000 00000000 00000000 00000000  ................
29400060: 00000000 00000000 00000000 00000000  ................
29400070: 00000000 08050000 00000002 00000000  ................
StarFive # md 29480000 0x20
29480000: 00000000 00000000 00000000 00000000  ................
29480010: 00000000 00000000 00000000 00000000  ................
29480020: 00000000 00000000 00000000 00000000  ................
29480030: 00000000 00000000 00000000 00000000  ................
29480040: 00000000 00000000 00000000 00000000  ................
29480050: 00000000 00000000 00000000 00000000  ................
29480060: 00000000 00000000 00000000 00000000  ................
29480070: 00000000 00000000 00000000 00000000  ................
StarFive # md 295C0000 0x20
295c0000: 00000004 00000004 00000004 0000000c  ................
295c0010: 80000000 80000000 80000000 80000000  ................
295c0020: 80000000 00000000 00000000 00000000  ................
295c0030: 00000000 00000000 00000000 80000000  ................
295c0040: 80000000 80000000 00000000 00000777  ............w...
295c0050: 00000000 00000000 00000000 00000000  ................
295c0060: 00000000 00000000 00000000 00000000  ................
295c0070: 00000000 00000000 00000000 00000000  ................
StarFive # 
```

TODO: Why is Reset at 295C0048?

TODO: Did we overwrite any default values for Clock Mux and Multiplier?

[Revision and Chip ID](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361) are at...

```c
#define DC_HW_REVISION          0x0024
#define DC_HW_CHIP_CID          0x0030
```

U-Boot Commands...

```text
## Dump the Hardware Revision
md 29400024 1

## Dump the Chip ID
md 29400030 1
```

We see...

```text
StarFive # md 29400024 1
29400024: 00005720                              W..
StarFive # md 29400030 1
29400030: 0000030e                             ....
StarFive # 
```

Based on [vs_dc_hw.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361...

- revision = 0x5720
	
  Which means hw.rev = DC_REV_0

- chip id = 0x30e

Which looks correct yay!

FYI: 295C004c shows 0x777, but can't be cleared. Why? Is it showing the current Reset Status?

```text
StarFive # md 295C0038 1
295c0038: 00000000                             ....
StarFive # md 295C004c 1
295c004c: 00000777                             w...
StarFive # md 295C0048 1
295c0048: 00000000                             ....
StarFive # mw 295C004c 0 1
StarFive # 
StarFive # md 295C004c 1
295c004c: 00000777                             w...
StarFive # md 29400000 0x20
29400000: 00000900 80010000 00222200 00000000  ........."".....
29400010: 00000000 00000004 14010000 000b4b41  ............AK..
29400020: 00008200 00005720 20210316 16015600  .... W....! .V..
29400030: 0000030e a0600084 00000000 00000000  ......`.........
29400040: 00000000 00000000 00000000 00000000  ................
29400050: 00000000 00000000 00000000 00000000  ................
29400060: 00000000 00000000 00000000 00000000  ................
29400070: 00000000 08050000 00000002 00000000  ................
StarFive # md 29480000 0x20
29480000: 00000000 00000000 00000000 00000000  ................
29480010: 00000000 00000000 00000000 00000000  ................
29480020: 00000000 00000000 00000000 00000000  ................
29480030: 00000000 00000000 00000000 00000000  ................
29480040: 00000000 00000000 00000000 00000000  ................
29480050: 00000000 00000000 00000000 00000000  ................
29480060: 00000000 00000000 00000000 00000000  ................
29480070: 00000000 00000000 00000000 00000000  ................
StarFive # md 295C0000 0x20
295c0000: 00000004 00000004 00000004 0000000c  ................
295c0010: 80000000 80000000 80000000 80000000  ................
295c0020: 80000000 00000000 00000000 00000000  ................
295c0030: 00000000 00000000 00000000 80000000  ................
295c0040: 80000000 80000000 00000000 00000777  ............w...
295c0050: 00000000 00000000 00000000 00000000  ................
295c0060: 00000000 00000000 00000000 00000000  ................
295c0070: 00000000 00000000 00000000 00000000  ................
StarFive # 
```

U-Boot Script:

```text
## Create the command to power up the Display Controller
setenv display_on 'mw 295C0010 0x80000000 1 ; mw 295C0014 0x80000000 1 ; mw 295C0018 0x80000000 1 ; mw 295C001c 0x80000000 1 ; mw 295C0020 0x80000000 1 ; mw 295C003c 0x80000000 1 ; mw 295C0040 0x80000000 1 ; mw 295C0044 0x80000000 1 ; mw 295C0048 0 1 ; md 29400000 0x20 ; '

## Check that it's correct
printenv display_on

## Save it for future reboots
saveenv

## Run the command to power up the Video Output
run video_on

## Run the command to power up the Display Controller
run display_on
```

We should see...

```text
StarFive # run video_on
295c0000: 00000004 00000004 00000004 0000000c  ................
295c0010: 00000000 00000000 00000000 00000000  ................
295c0020: 00000000 00000000 00000000 00000000  ................
295c0030: 00000000 00000000 00000000 00000000  ................
295c0040: 00000000 00000000 00000fff 00000000  ................
295c0050: 00000000 00000000 00000000 00000000  ................
295c0060: 00000000 00000000 00000000 00000000  ................
295c0070: 00000000 00000000 00000000 00000000  ................

StarFive # run display_on
29400000: 00000900 80010000 00222200 00000000  ........."".....
29400010: 00000000 00000004 14010000 000b4b41  ............AK..
29400020: 00008200 00005720 20210316 16015600  .... W....! .V..
29400030: 0000030e a0600084 00000000 00000000  ......`.........
29400040: 00000000 00000000 00000000 00000000  ................
29400050: 00000000 00000000 00000000 00000000  ................
29400060: 00000000 00000000 00000000 00000000  ................
29400070: 00000000 08050000 00000002 00000000  ................
```

# JH7110 System Configuration Registers

TODO

[SYS SYSCON: System Configuration Registers](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/sys_syscon.html)

From [System Memory Map](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/system_memory_map.html), System SYSCON is at 0x1303_0000

```text
# md 13030000
13030000: 00000000 00000000 00000000 00000000  ................
13030010: 00000000 00d54d54 034fea80 0000007d  ....TM....O.}...
13030020: 45555555 042ba603 45e00000 00c7a60c  UUUE..+....E....
13030030: 45333333 00000002 00000000 00000000  333E............
13030040: 00000000 00000000 00000000 00000000  ................
13030050: 00000000 00000000 00000000 00000000  ................
13030060: 00000002 00000000 2a000000 00000000  ...........*....
13030070: 2a000000 00000000 2a000000 00000000  ...*.......*....
13030080: 2a000000 01aa8000 00000d54 6aa00000  ...*....T......j
13030090: 00000004 00000000 00000000 00042600  .............&..
130300a0: 00000000 00000000 00000000 00000000  ................
130300b0: 00000000 00000000 00000000 00000000  ................
130300c0: 00000000 00000000 00000000 00000000  ................
130300d0: 00000000 00000000 00000000 00000000  ................
130300e0: 00000000 00000000 00000000 00000000  ................
130300f0: 00000000 00000000 00000000 00000000  ................
```

TODO: Which SYSCON Registers are already configured?

# JH7110 Bus Connection

TODO

From [Bus Connection](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/bus_connection.html):

![Bus Connection](https://doc-en.rvspace.org/JH7110/TRM/Image/RD/JH7110/stg_mtrx_connection17.png)

TODO: Do we need to bother with Bus Connections?

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/display3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/display3.md)
