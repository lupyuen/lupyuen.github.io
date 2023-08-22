# RISC-V Star64 JH7110: Inside the Display Controller

📝 _26 Aug 2023_

![Display Driver for StarFive JH7110 SoC](https://lupyuen.github.io/images/display2-title.jpg)

Today we look deep inside the __Display Controller__ of the [__RISC-V StarFive JH7110 SoC__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) and figure out how it works.

_But the JH7110 Display Controller is NOT documented!_

Indeed! The [__Official JH7110 Doc__](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/source_code_structure_display.html) only points to the [__Linux Driver Source Code__](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/source_code_structure_display.html).

(Plus a smattering of [__Display Registers__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/dom_vout_syscon.html))

_Sounds a little disturbing?_

Yeah goodbye olden days of [__Documented Display Registers__](https://lupyuen.github.io/articles/de#appendix-programming-the-allwinner-a64-display-engine)! (Like for [__Allwinner A64__](https://lupyuen.github.io/articles/de#appendix-programming-the-allwinner-a64-display-engine))

But no worries! We're here to decipher the __Driver Source Code__ and document everything ourselves...

- What's inside the __Direct Rendering Manager (DRM) Driver__ for JH7110

- How it controls the __Display Registers__

- To handle the __Display Pipeline__, __Display Planes__ and __Framebuffers__

- And how it talks to __HDMI and MIPI DSI__ (Display Serial Interface)

- Also how we might __implement the driver__ ourselves (without Linux)

_Why are we doing this?_

We're building a __HDMI Display Driver__ for [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/release) (RTOS) on the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) SBC. (Based on JH7110, just like VisionFive2)

Our analysis today will be super useful for creating our __HDMI Driver for NuttX__ on Star64. (Pic below)

And hopefully this article will be helpful for __porting other Operating Systems__ to JH7110!

![Pine64 Star64 RISC-V SBC](https://lupyuen.github.io/images/linux-title.jpg)

# JH7110 Docs and Source Code

_What exactly is documented for JH7110 Display Controller?_

Officially these are the __JH7110 Display Controller__ docs...

- [__Display Subsystem__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/display_subsystem.html)

- [__Display Controller Developing Guide__](http://doc-en.rvspace.org/VisionFive2/DG_Display/)

- [__SDK for HDMI__](http://doc-en.rvspace.org/VisionFive2/DG_HDMI/)

- [__MIPI LCD Developing and Porting Guide__](http://doc-en.rvspace.org/VisionFive2/DG_LCD/)

- [__GPU Developing and Porting Guide__](http://doc-en.rvspace.org/VisionFive2/DG_GPU/)

- [__Multimedia Developing Guide__](http://doc-en.rvspace.org/VisionFive2/DG_Multimedia/)

But the [__crucial docs are confidential__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/detail_info_display.html). (Sigh)

_What about the Driver Source Code?_

We have the official [__Linux Drivers__](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/source_code_structure_display.html) for the Display Controller...

- [__vs_dc.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c): Display Controller

- [__vs_dc_hw.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c): Framebuffer and Overlay (similar to A64 Display Engine)

- [__vs_drv.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c): Device for Direct Rendering Manager

- [__vs_crtc.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c): Display Pipeline (Colour / Gamma / LUT)

- [__vs_plane.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_plane.c): Display Plane

- [__vs_simple_enc.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_simple_enc.c): [Display Subsystem (DSS)](https://software-dl.ti.com/processor-sdk-linux/esd/docs/06_03_00_106/linux/Foundational_Components/Kernel/Kernel_Drivers/Display/DSS.html) Encoder

- [__vs_gem.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_gem.c): [Graphics Execution Manager](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#Graphics_Execution_Manager) (Memory Management Framework)

- [__vs_virtual.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_virtual.c): Virtual Display

- [__vs_dc_dec.c__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_dec.c): Bitmap Decompression

  [(Build Instructions)](https://github.com/starfive-tech/linux/tree/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon)

_Phew so many Source Files!_

Yeah but they're super helpful for understanding the Inner Workings of our Display Controller!

We'll decipher the Driver Source Code in a while.

![JH7110 Display Subsystem Block Diagram](https://lupyuen.github.io/images/display2-vout_block_diagram18.png)

[_JH7110 Display Subsystem Block Diagram_](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/block_diagram_display.html)

# DC8200 Display Controller

_What's this DC8200?_

From the pic above, we see that JH7110 uses a __VeriSilicon DC8200 Dual Display Controller__ to drive these displays...

- __MIPI DPHY / DSI__: Display Serial Interface

  (For most LCD Panels, like in PineTab-V)

- __DPI__: Display Parallel Interface

  (For LCD Panels with Parallel RGB Interface)

- __HDMI Video Output__

The Display Output Ports are named __DPI0 and DPI1__.

[(NoC means __Network-on-Chip__)](https://en.wikipedia.org/wiki/Network_on_a_chip)

[(AXI is the __Advanced eXtensible Interface__)](https://en.wikipedia.org/wiki/Advanced_eXtensible_Interface)

These are the __Clock and Reset Signals__ for the Display Controller...

![JH7110 Display Subsystem Clock and Reset](https://lupyuen.github.io/images/display2-vout_clkrst18.png)

[_JH7110 Display Subsystem Clock and Reset_](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/clock_n_reset_display.html)

[(Remember to __Enable the Clocks__ and __Deassert the Resets__!)](https://lupyuen.github.io/articles/display2#appendix-jh7110-display-clock-and-reset)

The DC8200 Display Controller outputs to __2 displays simultaneously__ (like MIPI DSI + HDMI)...

![Block Diagram of DC8200 Display Controller](https://lupyuen.github.io/images/display2-Display_Block_Diagram.png)

[_Block Diagram of DC8200 Display Controller_](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/block_diagram_display.html)

[(AXI is the __Advanced eXtensible Interface__)](https://en.wikipedia.org/wiki/Advanced_eXtensible_Interface)

With support for...

- __Display Layers__: Overlays for Cursor, Video, Graphics

- __Output Control__: Blending, Gamma, 3D LUT, RGB-to-YUV, Dithering

We'll explain the Display Layers (Overlays) in a while.

_How are the Display Outputs mapped to MIPI DSI and HDMI?_

The [__Linux Device Tree__](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/device_tree_config_display.html) configures the mapping of Display Outputs to the Display Devices...

```text
## Configure DC8200 Display Controller
&dc8200 {

  ## Display Outputs are mapped to...
  dc_out: port {

    ## DPI0: HDMI
    dc_out_dpi0: endpoint@0 {
      reg = <0>;
      remote-endpoint = <&hdmi_input0>;
    };

    ## DPI1: HDMI LCDC
    dc_out_dpi1: endpoint@1 {
      reg = <1>;
      remote-endpoint = <&hdmi_in_lcdc>;
    };

    ## DPI2: MIPI DSI
    dc_out_dpi2: endpoint@2 {
      reg = <2>;
      remote-endpoint = <&mipi_in>;
    };
```

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/device_tree_config_display.html)

Let's dive into the Display Driver Code!

![Display Driver for StarFive JH7110 SoC](https://lupyuen.github.io/images/display2-title.jpg)

# DC8200 Driver for Direct Rendering Manager

_What's this DRM?_

[__Direct Rendering Manager (DRM)__](https://en.wikipedia.org/wiki/Direct_Rendering_Manager) is the Linux Subsystem that talks to Display Controllers. (Like the DC8200 Display Controller in JH7110)

The pic above shows the __DC8200 Driver for DRM__ (top left). It works like a façade for the other DC8200 Driver Modules. (Rest of the pic)

(Not to be confused with [__the other DRM__](https://en.wikipedia.org/wiki/Digital_rights_management), which is also video-related)

## DRM Operations

The DRM Driver for DC8200 is named __"starfive"__. These are the __DRM Operations__ supported by the driver: [vs_drv.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L125-L143)

```c
// DRM Driver for DC8200 Display Controller
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
  .major = 1,
  .minor = 0,
};
```

(Nothing to see here, mostly DRM Boilerplate)

(We'll come back to __fops__)

[(__Graphics Execution Manager "GEM"__ handles Memory Buffers)](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#Graphics_Execution_Manager)

[(__vs_gem__ functions are here)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_gem.c)

![DRM Sub-Drivers](https://lupyuen.github.io/images/jh7110-display2.jpg)

## DRM Sub-Drivers

_Where are the fun bits of our Display Driver?_

Remember our DRM Driver is only a façade. Most of the work is done by the __Sub-Drivers for DC8200__ (pic above): [vs_drv.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L301-L315)

```c
// Sub-Drivers for DC8200 Display Controller
static struct platform_driver *drm_sub_drivers[] = {

  // Display Controller Driver
  &dc_platform_driver,

#ifdef CONFIG_STARFIVE_INNO_HDMI
  // HDMI Controller Driver:
  // Inno HDMI 2.0 Transmitter for TSMC28HPC+
  &inno_hdmi_driver,
#endif

  // Simple Encoder Driver
  &simple_encoder_driver,

#ifdef CONFIG_VERISILICON_VIRTUAL_DISPLAY
  // Virtual Display Driver
  &virtual_display_platform_driver,
#endif
};
```

We'll see the __Display Controller Driver__ in a while.

_Who starts the Sub-Drivers?_

At startup, [__vs_drm_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L459-L472) (in the DRM Driver) registers two things...

- __DC8200 Sub-Drivers: [drm_sub_drivers](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L301-L315)__

- __DC8200 DRM Plaform Driver: [vs_drm_platform_driver](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L448-L457)__

That's how the Sub-Drivers are started.

## File Operations

_What's inside fops?_

__fops__ defines the __File Operations__ supported by our DRM Driver: [vs_drv.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L54-L63)

```c
// File Operations for DC8200 Display Controller
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

(Looks fairly standard for a DRM Driver)

[(__vs_gem_mmap__ is defined here)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_gem.c#L546-L561)

![Display Driver renders graphics to a Display Device](https://lupyuen.github.io/images/dsi3-steps.jpg)

# Inside the Display Driver

_What's inside a typical Display Driver?_

_How does it talk to the Display Hardware?_

Before we dive too deep into our Driver Code, let's talk about __Display Drivers__ and how they control the __Display Hardware__.

The pic above shows how a typical Display Driver will __render graphics__ to a Display Device...

- Our Apps will write the pixels into a __RAM Framebuffer__

- Inside the SoC is a __Display Engine__ that reads the Framebuffer (over DMA)

- And pushes a continuous stream of pixels to a __Display Device__

  (Over HDMI or MIPI Display Serial Interface)

_What's a Framebuffer?_

A __Framebuffer__ is just a region of RAM that stores pixels in a Colour Format. (Like ARGB 8888)

![Framebuffer](https://lupyuen.github.io/images/de2-fb.jpg)

__Multiple Framebuffers__ are supported. Framebuffers can be rendered as __Opaque or Semi-Transparent Overlays__...

![Overlays](https://lupyuen.github.io/images/de2-overlay.jpg)

To do this, we configure the __Display Pipeline__ to Blend the Framebuffers...

![Blender](https://lupyuen.github.io/images/de2-blender.jpg)

Internally, the Display Driver will manipulate the __Display Registers__ to...

1.  Configure the __Framebuffers__ (and their RAM Addresses)

1.  Configure the __Display Pipelines__ (for Overlay Blending)

1.  Configure the __Display Output__ (for the Display Device)

1.  __Commit the Display Configuration__ (to the Display Controller)

And that's how a typical Display Driver works in a Modern SoC!

[(Like for __Allwinner A64__)](https://lupyuen.github.io/articles/de3)

Heading back to our scheduled programming...

![DC8200 Display Controller Driver](https://lupyuen.github.io/images/jh7110-display3.jpg)

# DC8200 Display Controller Driver

The __DC8200 Display Controller Driver__ (pic above) is called by the the DC8200 DRM Driver. The driver exposes the Display Functions for...

- Initialisation of __Display Controller__

- Setup and Configuration of __Display Pipeline__

- Update of __Display Plane__

The Display Controller Driver is named __"vs-dc"__ (for VeriSilicon Display Controller): [vs_dc.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1642-L1649)

```c
struct platform_driver dc_platform_driver = {
  .probe  = dc_probe,
  .remove = dc_remove,
  .name   = "vs-dc"
```

[(__dc_probe__ is defined here)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1595-L1629)

[(__dc_remove__ is defined here)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1631-L1640)

These are the __Component Functions__ exposed by the Display Controller Driver: [vs_dc.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1584-L1587)

```c
const struct component_ops dc_component_ops = {
  .bind   = dc_bind,
  .unbind = dc_unbind,
};
```

_What happens at startup?_

At startup, the DRM Driver calls our __Display Controller Driver__ at...

- [__dc_bind__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1421-L1573) and [__dc_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L644-L722) to setup the [__Clock and Reset Signals__](https://lupyuen.github.io/articles/display2#appendix-jh7110-display-clock-and-reset)

  [(More about __dc_bind__)](https://lupyuen.github.io/articles/display2#dc_bind)

  [(And __dc_init__)](https://lupyuen.github.io/articles/display2#dc_init)

Which calls our __Display Hardware Driver__ at...

- [__dc_hw_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361) to update the __Display Registers__

As we'll see in the next section.

_That's all for our Display Controller Driver?_

There's more! We'll come back to our Display Controller Driver for handling the Display Pipeline and Display Plane.

![DC8200 Display Hardware Driver](https://lupyuen.github.io/images/jh7110-display4.jpg)

# DC8200 Display Hardware Driver

_Now we do the exciting bit?_

Finally! The __Display Hardware Driver__ (pic above) is called by the Display Controller Driver (previous section) to manipulate the Display Hardware Registers and...

- Initialise the __Display Controller__

- Setup and Configure the __Display Pipeline__

- Update the __Display Plane__

(This is the driver that we'll reimplement in NuttX!)

Earlier we saw [__dc_init__](https://lupyuen.github.io/articles/display2#dc8200-display-controller-driver) (from Display Controller Driver) calling the Display Hardware Driver at startup.

Here's what happens inside [__dc_hw_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361)...

1.  Read the __Hardware Revision and Chip ID__

1.  Initialise every __Display Plane__ (Layer)

1.  Initialise every __Display Panel__ (and Cursor)

_Why read the Hardware Revision?_

Depending on the __Hardware Revision__, the DC8200 Display Controller works a little differently.

Assuming that our Display Controller is [__DC_REV_2__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.h#L237-L241) (HW_REV_5721_310)...

- __[dc_info](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1129-L1149) (Display Controller Info)__ says that 2 Display Panels and 8 Display Planes (Layers) are supported...

  ```c
  // Display Controller Info
  static const struct vs_dc_info dc_info[] = {
    ...
    {
      // For DC_REV_2:
      .name      = "DC8200",
      .panel_num = 2,
      .plane_num = 8,
      .planes    = dc_hw_planes[DC_REV_2],
      .layer_num = 6,
      .max_bpc   = 10,
      .color_formats =
        DRM_COLOR_FORMAT_RGB444 |
        DRM_COLOR_FORMAT_YCRCB444 |
        DRM_COLOR_FORMAT_YCRCB422 |
        DRM_COLOR_FORMAT_YCRCB420,
      .gamma_size   = GAMMA_EX_SIZE,
      .gamma_bits   = 12,
      .pitch_alignment = 128,
      .pipe_sync    = false,
      .mmu_prefetch = false,
      .background   = true,
      .panel_sync   = true,
      .cap_dec      = false,
    }
  ```

- __[dc_hw_planes](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L863-L1083) (Display Planes Info)__ defines the 8 Display Planes (Layers)...

  | Z Pos | Layer | Min Size | Max Size |
  |:-----:|:------|:--------:|:--------:|
  | 0 | Primary | 0 x 0 | 4096 x 4096
  | 1 | Overlay | 0 x 0 | 4096 x 4096
  | 2 | Overlay_1 | 0 x 0 | 4096 x 4096
  | 3 | Primary_1 | 0 x 0 | 4096 x 4096
  | 4 | Overlay_2 | 0 x 0 | 4096 x 4096
  | 5 | Overlay_3 | 0 x 0 | 4096 x 4096
  | 255 | Cursor | 32 x 32 | 64 x 64
  | 255 | Cursor_1 | 32 x 32 | 64 x 64

  [(Plus a bunch of __Other Properties__)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L863-L1083)

_Why are the layers interleaved?_

That's because the Display Planes (Layers) will be rendered to __2 separate displays__ (HDMI + MIPI DSI)...

| Display 0 | Display 1 |
|:----------|:----------|
| Primary | Primary_1 |
| Overlay | Overlay_2 |
| Overlay_1 | Overlay_3 |
| Cursor | Cursor_1 |

![Block Diagram of DC8200 Display Controller](https://lupyuen.github.io/images/display2-Display_Block_Diagram.png)

[_Block Diagram of DC8200 Display Controller_](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/block_diagram_display.html)

Our Display Hardware Driver will do other fun things! Let's talk about the Display Pipelines and Display Planes...

![Setup Display Pipeline](https://lupyuen.github.io/images/jh7110-display5a.jpg)

# Setup Display Pipeline

Earlier we talked about [__Display Pipelines__](https://lupyuen.github.io/articles/display2#inside-the-display-driver) and how they...

- __Read pixels__ from one or more Framebuffers over DMA

- __Blend the Framebuffers__ / Display Planes / Layers into a single image

- __Apply bitmap effects__ like Gamma Correction

- __Push the image pixels__ to the Display Device (HDMI or MIPI DSI)

In Linux Direct Rendering Manager (DRM), the Display Pipeline is implemented as [__CRTC Functions__](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#KMS_device_model): [vs_dc.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1400-L1408)

```c
// Display Pipeline Functions for DC8200 Display Controller
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

_How do we create a Display Pipeline?_

From above, we see that DRM __creates the Display Pipeline__ (pic above) by calling our Display Controller Driver at...

- [__vs_dc_enable__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L740-L827), to prepare the Clock and Reset Signals

  [(More about __vs_dc_enable__)](https://lupyuen.github.io/articles/display2#vs_dc_enable)

Which calls...

- [__dc_hw_setup_display__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1480-L1487), from our Display Hardware Driver

_What's inside dc_hw_setup_display?_

In our Display Hardware Driver, [__dc_hw_setup_display__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1480-L1487) will...
1.  Copy the __Display Struct__
1.  Call [__setup_display_ex__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1971-L2030)

Then [__setup_display_ex__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1971-L2030) will...
1.  Set the __Colour Format__
1.  Call [__setup_display__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1865-L1969)

Finally [__setup_display__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1865-L1969) will do most of the work...
1.  Set the __DPI Config__
1.  Disable the __Display Panel__
1.  Set the __Horizontal Resolution and Sync__
1.  Set the __Vertical Resolution and Sync__
1.  Configure the __Framebuffer Sync Mode__
1.  Set the __Framebuffer Background Colour__
1.  Set the __Display Dither__
1.  Enable the __Display Panel__
1.  Set the __Overlay Configuration__
1.  Set the __Cursor Configuration__

_Who creates the Display Pipeline?_

To create the Display Pipeline, [__vs_dc_enable__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L740-L826) (from above) is called by [__vs_crtc_atomic_enable__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c#L265-L276)...

```c
// DC8200 Display Pipeline Helper Functions
static const struct drm_crtc_helper_funcs vs_crtc_helper_funcs = {
  .mode_fixup     = vs_crtc_mode_fixup,
  .atomic_enable  = vs_crtc_atomic_enable,
  .atomic_disable = vs_crtc_atomic_disable,
  .atomic_begin   = vs_crtc_atomic_begin,
  .atomic_flush   = vs_crtc_atomic_flush,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c#L338-L344)

Which is called by the Linux [__DRM Atomic Helper__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_atomic_helper.c#L1323-L1408).

(We'll see __vs_crtc_atomic_flush__ in the next section)

[(More about __DRM Atomic Display__)](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#Atomic_Display)

And that's how we create a Display Pipeline! Now we commit the Display Pipeline...

![Commit Display Pipeline](https://lupyuen.github.io/images/jh7110-display5b.jpg)

# Commit Display Pipeline

_Why will we Commit a Display Pipeline?_

A Display Pipeline won't render any pixels... Until we __Commit the Display Pipeline__! (Pic above)

To Commit the Display Pipeline, the Linux Direct Rendering Manager (DRM) calls our Display Controller Driver at...

- [__vs_dc_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1381-L1398), which calls...

- [__dc_hw_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L2038-L2076), from our Display Hardware Driver

_What's inside dc_hw_commit?_

In our Display Hardware Driver, [__dc_hw_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L2038-L2076) will...

1.  Call [__gamma_ex_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1548-L1574) to commit the Gamma Correction
1.  Call [__plane_ex_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1768-L1863) commit the Display Plane
1.  Update the __Cursor and QoS__

_What happens in plane_ex_commit?_

[__plane_ex_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1768-L1863) will...
1.  Set the __Colour Space__
1.  Set the __Gamma Correction__
1.  Call [__plane_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1576-L1766)

Then [__plane_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1576-L1766) will do this for every __Display Plane__ (Layer)...
1.  Set the __Framebuffer YUV Address and Stride__
1.  Set the __Framebuffer Width and Height__
1.  __Clear the Framebuffer__
1.  Configure the __Primary and Non-Primary Framebuffers__
1.  Enable __Framebuffer Scaling__ (X and Y)
1.  Set the __Framebuffer Offset__ (X and Y)
1.  Set the __Framebuffer Blending__
1.  Set the __Colour Key__ (Transparency)
1.  Set the __ROI__

_Who Commits the Display Pipeline?_

To Commit the Display Pipeline, [__vs_dc_commit__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1381-L1398) is called by [__vs_crtc_atomic_flush__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c#L320-L336)...

Which is called by the Linux [__DRM Atomic Helper__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_atomic_helper.c#L2445-L2570).

[(More about __DRM Atomic Display__)](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#Atomic_Display)

![Update Display Plane](https://lupyuen.github.io/images/jh7110-display6.jpg)

# Update Display Plane

One last thing for today: How to __Update the Display Plane__. (Pic above)

(A Display Plane is a Layer of Pixels / Framebuffer that will be blended into the final image by a Display Pipeline)

Our Display Controller Driver exposes these __Display Plane Functions__: 
[vs_dc.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1410-L1414)

```c
// Display Plane Functions for DC8200
static const struct vs_plane_funcs dc_plane_funcs = {
  .update  = vs_dc_update_plane,
  .disable = vs_dc_disable_plane,
  .check   = vs_dc_check_plane,
};
```

To update the Display Plane, the Linux Direct Rendering Manager (DRM) calls our Display Controller Driver at...

- [__vs_dc_update_plane__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1262-L1280)

Which calls...

1.  [__update_plane__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1153-L1196) (Update Plane)
1.  [__update_qos__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1198-L1220) (Update QoS) 
1.  [__update_cursor_plane__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1241-L1260) (Update Cursor Plane)

_What's inside update_plane?_

[__update_plane__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1153-L1196) (from our Display Controller Driver) will update the Display Plane...

1.  Call [__update_fb__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L973-L1014) to set the __Framebuffer Addresses__
1.  Call [__update_roi__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1097-L1127) to set the __ROI__
1.  Call [__update_scale__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L936-L971) to set the __Scaling__
1.  Call [__update_degamma__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1090-L1095) to set the __Degamma Correction__
1.  Set the __Start and End Position__ (X and Y)
1.  Set the __Blending Alpha and Mode__
1.  Set the __Colour Management__
1.  Call [__dc_hw_update_plane__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1368-L1399) 

Then [__dc_hw_update_plane__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1368-L1399) (from our Display Hardware Driver) will...
1.  Copy the __Framebuffer__
1.  Copy the __Scaling__
1.  Copy the __Position__
1.  Copy the __Blending__

_Who calls our driver to update the Display Plane?_

To update the Display Plane, [__vs_dc_update_plane__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1262-L1280) is called by [__vs_plane_atomic_update__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_plane.c#L268-L301)...

```c
// DC8200 Display Plane Helper Functions
const struct drm_plane_helper_funcs vs_plane_helper_funcs = {
  .atomic_check   = vs_plane_atomic_check,
  .atomic_update  = vs_plane_atomic_update,
  .atomic_disable = vs_plane_atomic_disable,
};
```

[(Source)](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_plane.c#L314-L318)

Which is called by the Linux [__DRM Atomic Helper__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_atomic_helper.c#L2445-L2570).

[(More about __DRM Atomic Display__)](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#Atomic_Display)

![Yocto Linux with KDE Plasma on Star64 HDMI](https://lupyuen.github.io/images/star64-plasma.jpg)

[_Yocto Linux with KDE Plasma on Star64 HDMI_](https://lupyuen.github.io/articles/linux)

# Unsolved Mysteries

_We're ready to build our NuttX Display Driver for JH7110?_

Not quite. We have a bit more to explore, like the __HDMI Controller for JH7110__...

- [__HDMI Display for JH7110__](https://github.com/lupyuen/nuttx-star64#hdmi-display-for-star64-jh7110)

- [__HDMI Controller for JH7110__](https://github.com/lupyuen/nuttx-star64#hdmi-controller-for-star64-jh7110)

- [__HDMI Controller Driver__](https://github.com/lupyuen/nuttx-star64#call-flow-for-hdmi-controller-driver)

- [__Test HDMI for JH7110__](https://github.com/lupyuen/nuttx-star64#test-hdmi-for-star64-jh7110)

  [(__Justin / Fishwaldo__ suggests that we check out the simpler HDMI Driver in U-Boot)](https://fosstodon.org/@Fishwaldo/110902984442385966)

When we port NuttX to the __PineTab-V Tablet__, we'll need drivers for __MIPI DSI and LCD Panel__...

- [__LCD Panel for Star64 JH7110__](https://github.com/lupyuen/nuttx-star64#lcd-panel-for-star64-jh7110)

- [__PineTab-V Factory Test Code__](https://github.com/lupyuen/nuttx-star64#pinetab-v-factory-test-code)

  [(__LCD Panel in PineTab-V__ is BOE TH101MB31IG002-28A)](https://fosstodon.org/@Fishwaldo/110902984462760802)

We might also need the __Framebuffer Driver__ and __Virtual Display Driver__....

- [__DC8200 Framebuffer Driver__](https://lupyuen.github.io/articles/display2#appendix-dc8200-framebuffer-driver)

- [__DC8200 Virtual Display Driver__](https://github.com/lupyuen/nuttx-star64#call-flow-for-dc8200-virtual-display-driver)

_Sounds like a lot of work!_

Yeah we'll probably [__prototype our new driver in Zig__](https://lupyuen.github.io/articles/dsi2) before converting to C. Stay tuned for updates!

[(Slightly annoying that New Zig won't run on my Old Mac)](https://github.com/lupyuen/pinephone-lvgl-zig#zig-version)

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

> ![DC8200 Framebuffer Driver](https://lupyuen.github.io/images/jh7110-display7.jpg)

# Appendix: DC8200 Framebuffer Driver

At startup, [__vs_drm_bind__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L193-L271) (from DRM Driver) calls [__vs_mode_config_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L178-L191) to register the Framebuffer Driver. (Pic above)

The Framebuffer Driver exposes the following functions: [vs_fb.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L166-L172)

```c
// DC8200 Framebuffer Functions
static const struct drm_mode_config_funcs vs_mode_config_funcs = {
  .fb_create       = vs_fb_create,
  .get_format_info = vs_get_format_info,
  .output_poll_changed = drm_fb_helper_output_poll_changed,
  .atomic_check    = drm_atomic_helper_check,
  .atomic_commit   = drm_atomic_helper_commit,
};
```

_Who creates the Framebuffer?_

To create the Framebuffer, [__vs_fb_create__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L60-L123) is called by [__drm_framebuffer__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_framebuffer.c#L286-L329) (from Linux DRM).

To get the Framebuffer Formats, [__vs_get_format_info__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L155-L164) is called by [__drm_fourcc__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_fourcc.c#L302-L325) (from Linux DRM).

Framebuffer Formats are defined in [__vs_formats__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_fb.c#L134-L139).

![JH7110 Display Subsystem Clock and Reset](https://lupyuen.github.io/images/display2-vout_clkrst18.png)

[_JH7110 Display Subsystem Clock and Reset_](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/clock_n_reset_display.html)

# Appendix: JH7110 Display Clock and Reset

TODO: Reconcile the Clock and Reset Names

[DOM VOUT CRG](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/dom_vout_crg.html)

![DC8200 Display Controller Driver](https://lupyuen.github.io/images/jh7110-display3.jpg)

## dc_bind

At startup, the DRM Driver calls our __Display Controller Driver__ at [__dc_bind__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1421-L1573) to setup the [__Clock and Reset Signals__](https://lupyuen.github.io/articles/display2#appendix-jh7110-display-clock-and-reset). (Pic above)

[__dc_bind__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1421-L1573) will do the following...

1.  Call [__dc_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L644-L722)

    [(Explained here)](https://lupyuen.github.io/articles/display2#dc_init)

1.  Attach __I/O MMU Device__

1.  For Each Panel: Create __Display Pipeline__

1.  For Each Plane: Create __Display Plane__

1.  Update __Pitch Alignment__

1.  Disable Clock __vout_top_lcd__

1.  Assert __DC8200 Reset__

1.  Disable __DC8200 Clock__

1.  Disable Clock __v_out_top__

1.  Disable Clock __DC vout__

![DC8200 Display Controller Driver](https://lupyuen.github.io/images/jh7110-display3.jpg)

## dc_init

At startup, the DRM Driver calls our __Display Controller Driver__ at [__dc_bind__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1421-L1573), which calls [__dc_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L644-L722) to setup the [__Clock and Reset Signals__](https://lupyuen.github.io/articles/display2#appendix-jh7110-display-clock-and-reset). (Pic above)

[__dc_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L644-L722) will do the following...

1.  Enable Clock __dc_vout_clk__

1.  Deassert __DC8200 Reset__

1.  Enable Clock __vout_top_lcd__

1.  Deassert __vout_reset__

1.  Update the [__DSS Registers__](https://software-dl.ti.com/processor-sdk-linux/esd/docs/06_03_00_106/linux/Foundational_Components/Kernel/Kernel_Drivers/Display/DSS.html) with this Mystery Code:

    ```c
    #ifdef CONFIG_DRM_I2C_NXP_TDA998X
      // tda998x-rgb2hdmi. For HDMI only?
      regmap_update_bits(dc->dss_regmap, 0x4, BIT(20), 1<<20);
    #endif

    #ifdef CONFIG_STARFIVE_DSI
      // For DSI only?
      regmap_update_bits(dc->dss_regmap, 0x8, BIT(3), 1<<3);
    #endif
    ```

1.  Call [__dc_hw_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361)

    [(Explained here)](https://lupyuen.github.io/articles/display2#dc8200-display-hardware-driver)

![Setup Display Pipeline](https://lupyuen.github.io/images/jh7110-display5a.jpg)

## vs_dc_enable

From above, we see that DRM __creates the Display Pipeline__ (pic above) by calling our Display Controller Driver at [__vs_dc_enable__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L740-L827), to prepare the Clock and Reset Signals.

[__vs_dc_enable__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L740-L827) will do the following...

1.  Enable Clock __dc_vout_clk__

1.  Deassert __DC8200 Reset__

1.  Enable Clock __vout_top_lcd__

1.  Update the [__DSS Registers__](https://software-dl.ti.com/processor-sdk-linux/esd/docs/06_03_00_106/linux/Foundational_Components/Kernel/Kernel_Drivers/Display/DSS.html) with this Mystery Code:

    ```c
    regmap_update_bits(dc->dss_regmap, 0x4, BIT(20), 1<<20);
    regmap_update_bits(dc->dss_regmap, 0x8, BIT(3), 1<<3);
    ```

    [(Similar to the Mystery Code in __dc_init__)](https://lupyuen.github.io/articles/display2#dc_init)

1.  Call [__dc_hw_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361)

    [(Explained here)](https://lupyuen.github.io/articles/display2#dc8200-display-hardware-driver)

1.  Set the __Display Struct__: Bus Format, Horz Sync, Vert Sync, Sync Mode, Background Colour, Sync Enable and Dither Enable

1.  If Display is __MIPI DSI__:

    Set the Clock Rate for __dc8200_pix0__, __dc8200_clk_pix1__ and __vout_top_lcd__

1.  If Display is __HDMI__:

    Set the Clock __hdmitx0_pixelclk__

1.  Call [__dc_hw_setup_display__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1480-L1487)

    [(Explained here)](https://lupyuen.github.io/articles/display2#setup-display-pipeline)
