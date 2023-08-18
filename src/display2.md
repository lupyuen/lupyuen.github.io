# RISC-V Star64 JH7110: Inside the Display Controller

📝 _16 Aug 2023_

![TODO](https://lupyuen.github.io/images/display2-title.jpg)

TODO

[__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/nuttx2) (RTOS) now officially supports [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer! (Pic below)

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html), the same SoC in VisionFive2)

# HDMI Display for Star64 JH7110

TODO

_Will NuttX work with the HDMI Display on Star64?_

Let's find out! Maybe our HDMI code will be reused for PineTab-V's MIPI DSI Display Panel. Here are the official docs...

- [Display Subsystem](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/display_subsystem.html)

- [SDK for HDMI](http://doc-en.rvspace.org/VisionFive2/DG_HDMI/)

- [Display Controller Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_Display/)

- [GPU Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/DG_GPU/)

- [Multimedia Developing Guide](http://doc-en.rvspace.org/VisionFive2/DG_Multimedia/)

- [MIPI LCD Developing and Porting Guide](http://doc-en.rvspace.org/VisionFive2/DG_LCD/)

From the docs above we have the [Display Subsystem Block Diagram](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/block_diagram_display.html)...

![Display Subsystem Block Diagram](https://doc-en.rvspace.org/JH7110/TRM/Image/RD/JH7110/vout_block_diagram18.png)

[(Source)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/block_diagram_display.html)

Which says that JH7110 uses a __DC8200 Dual Display Controller__ to drive the MIPI DSI and HDMI Displays.

[(But the DC8200 docs are confidential sigh)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/detail_info_display.html)

And we have the [Display Subsystem Clock and Reset](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/clock_n_reset_display.html)...

![Display Subsystem Clock and Reset](https://doc-en.rvspace.org/JH7110/TRM/Image/RD/JH7110/vout_clkrst18.png)

[(Source)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/clock_n_reset_display.html)

So to make HDMI work on JH7110, we need a create a NuttX Driver for the DC8200 Display Controller...

# DC8200 Display Controller for Star64 JH7110

TODO

Let's talk about the __DC8200 Dual Display Controller__.

[(But the DC8200 docs are confidential sigh)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/detail_info_display.html)

Here's the [Block Diagram of DC8200 Display Controller](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/block_diagram_display.html)...

![Block Diagram of DC8200 Display Controller](https://doc-en.rvspace.org/VisionFive2/DG_Display/Image/JH7110_SDK/Display_Block_Diagram.png)

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/block_diagram_display.html)

(Display Devices refer to MIPI DPHY and HDMI, interchangeable)

Here are the [Linux Drivers for DC8200 Display Controller](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/source_code_structure_display.html)...

- [vs_dc.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c): Display Controller

- [vs_dc_hw.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c): Framebuffer and Overlay (similar to A64 Display Engine)

- [vs_drv.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c): Device for Direct Rendering Manager

- [vs_crtc.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c): Display Pipeline (Colour / Gamma / LUT)

- [vs_plane.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_plane.c): Display Plane

- [vs_simple_enc.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_simple_enc.c): [Display Subsystem (DSS)](https://software-dl.ti.com/processor-sdk-linux/esd/docs/06_03_00_106/linux/Foundational_Components/Kernel/Kernel_Drivers/Display/DSS.html) Encoder

- [vs_gem.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_gem.c): [Graphics Execution Manager](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#Graphics_Execution_Manager) (Memory Management Framework)

- [vs_virtual.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_virtual.c): Virtual Display

- [vs_dc_dec.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_dec.c): Bitmap Decompression

[(See the Notes here)](https://github.com/starfive-tech/linux/tree/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon)

We'll see the Call Flow in a while.

Are these used?

- [vs_dc_mmu.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_mmu.c): Memory Mapping

- [vs_fb.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c): GEM Memory Mapping for Framebuffer

Here's the (partial) [Linux Device Tree for DC8200](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/device_tree_config_display.html)...

```text
&dc8200 {
  status = "okay";

  dc_out: port {
    #address-cells = <1>;
    #size-cells = <0>;
    dc_out_dpi0: endpoint@0 {
      reg = <0>;
      remote-endpoint = <&hdmi_input0>;
    };
    dc_out_dpi1: endpoint@1 {
      reg = <1>;
      remote-endpoint = <&hdmi_in_lcdc>;
    };

    dc_out_dpi2: endpoint@2 {
      reg = <2>;
      remote-endpoint = <&mipi_in>;
    };
  };
};
```

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/device_tree_config_display.html)

HDMI I2C Encoder in JH7110 is the [NXP Semiconductors TDA998X HDMI Encoder](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/kernel_menu_config_diplay.html)

Next we need to create a NuttX Driver for the HDMI Controller...

# HDMI Controller for Star64 JH7110

TODO

The HDMI Controller for JH7110 is [Inno HDMI 2.0 Transmitter For TSMC28HPC+](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/detail_info_display.html).

Based on [JH7110 HDMI Developing Guide](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/JH7110_SDK/source_code_structure_hdmi.html), the Linux Drivers for JH7110 HDMI (VeriSilicon Inno HDMI) are...

- [inno_hdmi.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/inno_hdmi.c)

- [inno_hdmi.h](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/inno_hdmi.h)

The [Linux Device Tree](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/JH7110_SDK/device_tree_hdmi.html) looks like...

```text
hdmi: hdmi@29590000 {
    compatible = "starfive,jh7100-hdmi","inno,hdmi";
      reg = <0x0 0x29590000 0x0 0x4000>;
      interrupts = <99>;
      status = "disabled";
      clocks = <&clkvout JH7110_U0_HDMI_TX_CLK_SYS>,
        <&clkvout JH7110_U0_HDMI_TX_CLK_MCLK>,
        <&clkvout JH7110_U0_HDMI_TX_CLK_BCLK>,
        <&hdmitx0_pixelclk>;
      clock-names = "sysclk", "mclk","bclk","pclk";
      resets = <&rstgen RSTN_U0_HDMI_TX_HDMI>;
      reset-names = "hdmi_tx";
    };
...
&hdmi {
  status = "okay";
  pinctrl-names = "default";
  pinctrl-0 = <&inno_hdmi_pins>;

  hdmi_in: port {
    #address-cells = <1>;
    #size-cells = <0>;
    hdmi_in_lcdc: endpoint@0 {
      reg = <0>;
      remote-endpoint = <&dc_out_dpi1>;
    };
  };
};
```

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/JH7110_SDK/device_tree_hdmi.html)

We see the [HDMI Initialization Process](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/JH7110_SDK/initialization_process.html)...

![HDMI Initialization Process](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/Image/JH7110_SDK/HDMI_Init.svg)

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/JH7110_SDK/initialization_process.html)

And the [HDMI Plug and Unplug Process](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/JH7110_SDK/plug_n_unplug_process.html)...

![HDMI Plug and Unplug Process](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/Image/JH7110_SDK/HDMI_Pug_Unplug.svg)

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_HDMI/JH7110_SDK/plug_n_unplug_process.html)

# Test HDMI for Star64 JH7110

TODO

_How will we test the HDMI Display for Star64 JH7110?_

We run the [`modetest` command to test HDMI](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/test_example_display.html)...

```bash
modetest \
  -M starfive \
  -D 0 \
  -a \
  -s 116@31:1920x1080 \
  -P 39@31:1920x1080@RG16 \
  -Ftiles 
```

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/test_example_display.html)

`116@31:1920x1080` means `<Connector ID>@<CRTC ID>: <Resolution>`

`39@31:1920x1080@RG16` means `<Plane ID>@<CRTC ID>: <Resolution>@<Format>`

[(CRTC "CRT Controller" refers to the Display Pipeline)](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#KMS_device_model)

See also...

- [Before Debug](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/before_debug.html)

- [Debug Display](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/debug_hdmi.html)

TODO: What's inside the modetest app? [modetest.c](https://gitlab.freedesktop.org/mesa/drm/-/blob/main/tests/modetest/modetest.c)

TODO: What parameters does modetest pass to the DC8200 Driver?

TODO: Can we create a simpler modetest for our own testing on NuttX?

# Direct Rendering Manager Driver for DC8200

TODO

![JH7110 Linux Display Driver](https://lupyuen.github.io/images/jh7110-display.jpg)

Let's walk through the code in the Linux Driver for DC8200 Display Controller, to understand how we'll implement it in NuttX.

The DRM Driver is named "starfive"...

```c
// name = "starfive"
static struct platform_driver vs_drm_platform_driver = {
  .probe  = vs_drm_platform_probe,
  .remove = vs_drm_platform_remove,
  ...
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L448-L457)

Here are the DRM Operations supported by the driver...

```c
static struct drm_driver vs_drm_driver = {
  .driver_features    = DRIVER_MODESET | DRIVER_ATOMIC | DRIVER_GEM,
  .lastclose          = drm_fb_helper_lastclose,
  .prime_handle_to_fd = drm_gem_prime_handle_to_fd,
  .prime_fd_to_handle = drm_gem_prime_fd_to_handle,
  .gem_prime_import   = vs_gem_prime_import,
  .gem_prime_import_sg_table = vs_gem_prime_import_sg_table,
  .gem_prime_mmap     = vs_gem_prime_mmap,
  .dumb_create        = vs_gem_dumb_create,
#ifdef CONFIG_DEBUG_FS
  .debugfs_init       = vs_debugfs_init,
#endif
  .fops  = &fops,
  .name  = "starfive",
  .desc  = "VeriSilicon DRM driver",
  .date  = "20191101",
  .major = DRV_MAJOR,
  .minor = DRV_MINOR,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L125-L143)

The DRM Driver includes these Sub Drivers...

```c
static struct platform_driver *drm_sub_drivers[] = {
  /* put display control driver at start */
  &dc_platform_driver,

  /* connector */
#ifdef CONFIG_STARFIVE_INNO_HDMI
  &inno_hdmi_driver,
#endif

  &simple_encoder_driver,

#ifdef CONFIG_VERISILICON_VIRTUAL_DISPLAY
  &virtual_display_platform_driver,
#endif
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L301-L315)

(More about [dc_platform_driver](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1642-L1649) in the next section)

[vs_drm_init](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L459-L472) registers [drm_sub_drivers](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L301-L315) and [vs_drm_platform_driver](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L448-L457)
 at startup.

Here are the File Operations supported by the DRM Driver...

```c
static const struct file_operations fops = {
  .owner     = THIS_MODULE,
  .open      = drm_open,
  .release   = drm_release,
  .unlocked_ioctl = drm_ioctl,
  .compat_ioctl   = drm_compat_ioctl,
  .poll      = drm_poll,
  .read      = drm_read,
  .mmap      = vs_gem_mmap,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L54-L63)

[(More about Direct Rendering Manager)](https://en.wikipedia.org/wiki/Direct_Rendering_Manager)

# Call Flow for DC8200 Display Controller Driver

TODO

The DC8200 Controller Driver is named "vs-dc" (for VeriSilicon)...

```c
// name = "vs-dc"
struct platform_driver dc_platform_driver = {
  .probe  = dc_probe,
  .remove = dc_remove,
  ...
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1642-L1649)

Probe for Display Controller is implemented here: [dc_probe](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1595-L1629)

We see the Component Functions exposed by the driver...

```c
const struct component_ops dc_component_ops = {
  .bind   = dc_bind,
  .unbind = dc_unbind,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1584-L1587)

Bind to Display Controller is here...

- [dc_bind](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1421-L1573), which calls..

- [dc_init](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L644-L722), which calls...

- [dc_hw_init](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361)

Here are the Display Pipeline [(CRTC)](https://www.kernel.org/doc/html/v4.15/gpu/drm-kms.html) functions exposed by the driver...

```c
static const struct vs_crtc_funcs dc_crtc_funcs = {
  .enable        = vs_dc_enable,
  .disable       = vs_dc_disable,
  .mode_fixup    = vs_dc_mode_fixup,
  .set_gamma     = vs_dc_set_gamma,
  .enable_gamma  = vs_dc_enable_gamma,
  .enable_vblank = vs_dc_enable_vblank,
  .commit        = vs_dc_commit,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1400-L1408)

Enable Display Pipeline is implemented here...

- [vs_dc_enable](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L740-L826), which calls...

- [dc_hw_setup_display](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1480-L1487)

Enable Display Pipeline [vs_dc_enable](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L740-L826) is called by [vs_crtc_atomic_enable](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c#L265-L276)

Which is called by [drm_atomic_helper](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_atomic_helper.c#L1323-L1408)

```c
static const struct drm_crtc_helper_funcs vs_crtc_helper_funcs = {
  .mode_fixup     = vs_crtc_mode_fixup,
  .atomic_enable  = vs_crtc_atomic_enable,
  .atomic_disable = vs_crtc_atomic_disable,
  .atomic_begin   = vs_crtc_atomic_begin,
  .atomic_flush   = vs_crtc_atomic_flush,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c#L338-L344)

Commit Display Pipeline is here...

- [vs_dc_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1381-L1398), which calls...

- [dc_hw_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L2038-L2076)

Commit Display Pipeline [vs_dc_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1381-L1398) is called by [vs_crtc_atomic_flush](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c#L320-L336)

Which is called by [drm_atomic_helper](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_atomic_helper.c#L2445-L2570)

These are the exposed functions for the Display Plane...

```c
static const struct vs_plane_funcs dc_plane_funcs = {
  .update  = vs_dc_update_plane,
  .disable = vs_dc_disable_plane,
  .check   = vs_dc_check_plane,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1410-L1414)

Update Display Plane is here...

- [vs_dc_update_plane](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1262-L1280), which calls...

- [update_plane](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1153-L1196), which calls...

- [dc_hw_update_plane](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1368-L1399)

Update Display Plane [vs_dc_update_plane](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1262-L1280) is called by [vs_plane_atomic_update](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_plane.c#L268-L301)

Which is called by [drm_atomic_helper](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_atomic_helper.c#L2445-L2570)

```c
const struct drm_plane_helper_funcs vs_plane_helper_funcs = {
  .atomic_check   = vs_plane_atomic_check,
  .atomic_update  = vs_plane_atomic_update,
  .atomic_disable = vs_plane_atomic_disable,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_plane.c#L314-L318)

Refer to [Linux DRM Internals](https://www.kernel.org/doc/html/v4.15/gpu/drm-internals.html)

# Call Flow for DC8200 Display Hardware Driver

TODO

Display Planes Info: [dc_hw_planes](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L472-L1084)

Display Controller Info: [dc_info](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1086-L1150)

Initialise Display Hardware: [dc_hw_init](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361)
- Read the Hardware Revision and Chip ID
- Initialise every Layer / Display Plane
- Initialise every Panel (Cursor)

Commit Display Hardware: [dc_hw_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L2038-L2076)
- Call [gamma_ex_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1548-L1574)
- Call [plane_ex_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1768-L1863)
- Update Cursor
- Update QoS

Update Display Plane: [dc_hw_update_plane](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1368-L1399)
- Copy Framebuffer
- Copy Scale
- Copy Position
- Copy Blend

Display Hardware Functions:

```c
static const struct dc_hw_funcs hw_func = {
  .gamma   = &gamma_ex_commit,
  .plane   = &plane_ex_commit,
  .display = setup_display_ex,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L2032-L2036)

Setup Display (Upper Level): [dc_hw_setup_display](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1480-L1487)
- Copy Display Struct
- Call [setup_display_ex](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1971-L2030)

Setup Display (Extended): [setup_display_ex](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1971-L2030)
- Set Colour Format
- Call [setup_display](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1865-L1969)

Setup Display (Lower Level): [setup_display](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1865-L1969)
- Set DPI Config
- Disable Display Panel
- Set Display Horizontal Resolution
- Set Display Horizontal Sync
- Set Display Vertical Resolution
- Set Display Vertical Resolution Sync
- Configure Framebuffer Sync Mode
- Set Framebuffer Background Colour
- Set Display Dither
- Enable Display Panel
- Set Overlay Config
- Set Cursor Config

Commit Display Plane (Extended): [plane_ex_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1768-L1863)
- Set Colour Space
- Set Gamma
- Call [plane_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1576-L1766)

Commit Display Plane: [plane_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1576-L1766)
- For every Layer / Display Plane:
- Set Framebuffer YUV Address
- Set Framebuffer YUV Stride
- Set Framebuffer Width and Height
- Clear Framebuffer
- Set Primary Framebuffer Config
- Set Non-Primary Framebuffer Config
- Enable Framebuffer Scaling (X and Y)
- Set Framebuffer Offset (X and Y)
- Set Framebuffer Blending
- Set Colour Key / Transparency
- Set ROI

[plane_ex_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1768-L1863) and [gamma_ex_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1548-L1574) are called by [dc_hw_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L2038-L2076)

# Call Flow for DC8200 Framebuffer Driver

TODO

At startup, [vs_drm_bind](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L193-L271) calls [vs_mode_config_init](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L178-L191) to register the Framebuffer Driver: [vs_mode_config_funcs](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L166-L172).

Which is defined as...

```c
static const struct drm_mode_config_funcs vs_mode_config_funcs = {
  .fb_create       = vs_fb_create,
  .get_format_info = vs_get_format_info,
  .output_poll_changed = drm_fb_helper_output_poll_changed,
  .atomic_check    = drm_atomic_helper_check,
  .atomic_commit   = drm_atomic_helper_commit,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L166-L172)

[vs_fb_create](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L60-L123) is called by [drm_framebuffer](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_framebuffer.c#L286-L329)

[vs_get_format_info](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L155-L164) is called by [drm_fourcc](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_fourcc.c#L302-L325)

Framebuffer Formats: [vs_formats](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L134-L139)

# Call Flow for DC8200 Virtual Display Driver

TODO

```c
static const struct drm_connector_helper_funcs vd_connector_helper_funcs = {
  .get_modes    = vd_get_modes,
  .mode_valid   = vd_mode_valid,
  .best_encoder = vd_best_encoder,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_virtual.c#L197-L201)

Display Resolutions: [vd_get_modes](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_virtual.c#L153-L181)

```c
static const struct drm_connector_funcs vd_connector_funcs = {
  .fill_modes = drm_helper_probe_single_connector_modes,
  .destroy    = vd_connector_destroy,
  .detect     = vd_connector_detect,
  .atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
  .atomic_destroy_state   = drm_atomic_helper_connector_destroy_state,
  .reset = drm_atomic_helper_connector_reset,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_virtual.c#L215-L222)

```c
const struct component_ops vd_component_ops = {
  .bind   = vd_bind,
  .unbind = vd_unbind,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_virtual.c#L311-L314)

```c
// name = "vs-virtual-display"
struct platform_driver virtual_display_platform_driver = {
  .probe  = vd_probe,
  .remove = vd_remove,
  ...
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_virtual.c#L353-L360)

Display Pipelines:

```c
static const struct drm_crtc_funcs vs_crtc_funcs = {
  .set_config = drm_atomic_helper_set_config,
  .destroy    = vs_crtc_destroy,
  .page_flip  = drm_atomic_helper_page_flip,
  .reset      = vs_crtc_reset,
  .atomic_duplicate_state = vs_crtc_atomic_duplicate_state,
  .atomic_destroy_state   = vs_crtc_atomic_destroy_state,
  .atomic_set_property    = vs_crtc_atomic_set_property,
  .atomic_get_property    = vs_crtc_atomic_get_property,
  //.gamma_set    = drm_atomic_helper_legacy_gamma_set,
  .late_register  = vs_crtc_late_register,
  .enable_vblank  = vs_crtc_enable_vblank,
  .disable_vblank = vs_crtc_disable_vblank,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c#L207-L220)

Simple Encoder Driver:

```c
// name = "vs-simple-encoder"
struct platform_driver simple_encoder_driver = {
  .probe  = encoder_probe,
  .remove = encoder_remove,
  ...
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_simple_enc.c#L300-L307)

# Call Flow for HDMI Controller Driver

TODO


```c
// name = "innohdmi-starfive"
struct platform_driver inno_hdmi_driver = {
  .probe  = inno_hdmi_probe,
  .remove = inno_hdmi_remove,
  ...
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/inno_hdmi.c#L1155-L1163)

```c
static const struct drm_encoder_helper_funcs inno_hdmi_encoder_helper_funcs = {
  .enable     = inno_hdmi_encoder_enable,
  .disable    = inno_hdmi_encoder_disable,
  .mode_fixup = inno_hdmi_encoder_mode_fixup,
  .mode_set   = inno_hdmi_encoder_mode_set,
  .atomic_check = inno_hdmi_encoder_atomic_check,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/inno_hdmi.c#L651-L657)

MIPI DSI:

```c
// name = "dw-mipi-dsi"
struct platform_driver dw_mipi_dsi_driver = {
  .probe  = dsi_probe,
  .remove = dsi_remove,
  ...
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/dw_mipi_dsi.c#L1066-L1073)

```c
// name = "cdns-dsi"
static struct platform_driver cdns_dsi_platform_driver = {
  .probe  = cdns_dsi_drm_probe,
  .remove = cdns_dsi_drm_remove,
  ...
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/starfive_drm_dsi.c#L1679-L1687)

```c
static const struct component_ops dsi_component_ops = {
  .bind   = dsi_bind,
  .unbind = dsi_unbind,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/dw_mipi_dsi.c#L998-L1001)

```c
static const struct drm_bridge_funcs dw_mipi_dsi_bridge_funcs = {
  .mode_set  = bridge_mode_set,
  .enable    = bridge_enable,
  .post_disable = bridge_post_disable,
  .attach     = bridge_attach,
  .mode_fixup = bridge_mode_fixup,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/dw_mipi_dsi.c#L869-L875)

# LCD Panel for Star64 JH7110

TODO

Also in the JH7110 Display Docs: How to connect an LCD Panel to JH7110.

JH7110's MIPI DSI Controller is [Cadence MIPI DSI v1.3.1 TX Controller IP (DSITX)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/ic_specification_lcd.html)...

![Cadence MIPI DSI v1.3.1 TX Controller IP (DSITX)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/Image/JH7110_SDK/ic_spec.png)

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/ic_specification_lcd.html)

JH7110's MIPI DPHY Controller is [MIPI DPHY M31 (M31DPHYRX611TL028D_00151501)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/ic_specification_lcd.html)...

![MIPI DPHY M31 (M31DPHYRX611TL028D_00151501)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/Image/JH7110_SDK/MIPI_DPHY_M31.png)

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/ic_specification_lcd.html)

Refer to the...

- [Linux Display Driver](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/display_driver_locations_lcd.html)

- [Linux Device Tree](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/device_tree_configuration_lcd.html)

See also the Sample LCD Panel Code for Seeed LCD Panel...

- [Enable LCD](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/enable_lcd.html)

- [Disable LCD](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/disable_lcd.html)

- [Obtain LCD Information](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/obtain_lcd_information.html)

Here's the [LCD Initialisation Process](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/initalization_lcd.html)

![LCD Initialisation Process](https://doc-en.rvspace.org/VisionFive2/DG_LCD/Image/JH7110_SDK/LCD_Init.svg)

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/initalization_lcd.html)

And the [MIPI Parameter Configuration](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/mipi_configuration.html) for 1C2L (2-lane MIPI DSI) and 1C4L (4-lane MIPI DSI).

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/display2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/display2.md)
