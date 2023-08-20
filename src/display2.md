# RISC-V Star64 JH7110: Inside the Display Controller

📝 _16 Aug 2023_

![Display Driver for StarFive JH7110 SoC](https://lupyuen.github.io/images/display2-title.jpg)

Today we look inside the __Display Controller__ of the [__RISC-V StarFive JH7110 SoC__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) and figure out how it works.

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

![JH7110 Linux Display Driver](https://lupyuen.github.io/images/jh7110-display.jpg)

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
  .major = DRV_MAJOR,
  .minor = DRV_MINOR,
};
```

(Nothing to see here, mostly DRM Boilerplate)

(We'll come back to __fops__)

[(__Graphics Execution Manager "GEM"__ handles Memory Buffers)](https://en.wikipedia.org/wiki/Direct_Rendering_Manager#Graphics_Execution_Manager)

TODO: vs_gem_prime_import, vs_gem_prime_import_sg_table, vs_gem_prime_mmap, vs_gem_dumb_create

TODO: DRV_MAJOR, DRV_MINOR

TODO: Pic of Sub-Drivers

## DRM Sub-Drivers

_Where are the fun bits of our Display Driver?_

Remember our DRM Driver is only a façade. Most of the work is done by the __Sub-Drivers for DC8200__: [vs_drv.c](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_drv.c#L301-L315)

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

TODO: vs_gem_mmap

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

TODO: Pic of Display Controller dc_bind

# DC8200 Display Controller Driver

The __DC8200 Display Controller Driver__ is called by the the DC8200 DRM Driver. The driver exposes the Display Functions for...

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

TODO: dc_remove

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

  [(More about __dc_bind__ and __dc_init__)](https://lupyuen.github.io/articles/display2#appendix-jh7110-display-clock-and-reset)

Which calls our __Display Hardware Driver__ at...

- [__dc_hw_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361) to update the __Display Registers__

As we'll see in the next section.

_That's all for our Display Controller Driver?_

There's more! We'll come back to our Display Controller Driver for handling the Display Pipeline and Display Plane.

TODO: Pic of dc_hw_init

# DC8200 Display Hardware Driver

_Now we do the exciting bit?_

Finally! The __Display Hardware Driver__ is called by the Display Controller Driver (previous section) to manipulate the Display Hardware Registers and...

- Initialise the __Display Controller__

- Setup and Configure the __Display Pipeline__

- Update the __Display Plane__

(This is the driver that we'll reimplement in NuttX!)

Earlier we saw [__dc_init__](https://lupyuen.github.io/articles/display2#dc8200-display-controller-driver) (from Display Controller Driver) calling the Display Hardware Driver at startup.

Here's what happens inside [__dc_hw_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1301-L1361)...

1.  Read the __Hardware Revision and Chip ID__

1.  Initialise every __Display Plane__ (Layer)

1.  Initialise every __Display Panel__ (Cursor)

_Why read the Hardware Revision?_

TODO

```c
DC_REV_2,/* For HW_REV_5721_310 */
```

Display Controller Info: [dc_info](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1129-L1149)

```c
static const struct vs_dc_info dc_info[] = {
  ...
  {
    /* DC_REV_2 */
    .name			= "DC8200",
    .panel_num		= 2,
    .plane_num		= 8,
    .planes			= dc_hw_planes[DC_REV_2],
    .layer_num		= 6,
    .max_bpc		= 10,
    .color_formats	= DRM_COLOR_FORMAT_RGB444 |
              DRM_COLOR_FORMAT_YCRCB444 |
              DRM_COLOR_FORMAT_YCRCB422 |
              DRM_COLOR_FORMAT_YCRCB420,
    .gamma_size		= GAMMA_EX_SIZE,
    .gamma_bits		= 12,
    .pitch_alignment	= 128,
    .pipe_sync		= false,
    .mmu_prefetch	= false,
    .background		= true,
    .panel_sync		= true,
    .cap_dec		= false,
  },
```

Display Planes Info: [dc_hw_planes](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L863-L1083)

```c
static const struct vs_plane_info dc_hw_planes[][PLANE_NUM] = {
  ...
	{
    /* DC_REV_2 */
    {
    .name		 = "Primary",
    .id				= PRIMARY_PLANE_0,
    .type		 = DRM_PLANE_TYPE_PRIMARY,
    .num_formats = ARRAY_SIZE(primary_overlay_format1),
    .formats	 = primary_overlay_format1,
    .num_modifiers = ARRAY_SIZE(format_modifier1),
    .modifiers	 = format_modifier1,
    .min_width	 = 0,
    .min_height  = 0,
    .max_width	 = 4096,
    .max_height  = 4096,
    .rotation	 = DRM_MODE_ROTATE_0 |
             DRM_MODE_ROTATE_90 |
             DRM_MODE_ROTATE_180 |
             DRM_MODE_ROTATE_270 |
             DRM_MODE_REFLECT_X |
             DRM_MODE_REFLECT_Y,
    .blend_mode  = BIT(DRM_MODE_BLEND_PIXEL_NONE) |
             BIT(DRM_MODE_BLEND_PREMULTI) |
             BIT(DRM_MODE_BLEND_COVERAGE),
    .color_encoding = BIT(DRM_COLOR_YCBCR_BT709) |
              BIT(DRM_COLOR_YCBCR_BT2020),
    .degamma_size	= DEGAMMA_SIZE,
    .min_scale	 = FRAC_16_16(1, 3),
    .max_scale	 = FRAC_16_16(10, 1),
    .zpos		 = 0,
    .watermark	 = true,
    .color_mgmt  = true,
    .roi		 = true,
    },
    {
    .name		 = "Overlay",
    .id				= OVERLAY_PLANE_0,
    .type		 = DRM_PLANE_TYPE_OVERLAY,
    .num_formats = ARRAY_SIZE(primary_overlay_format1),
    .formats	 = primary_overlay_format1,
    .num_modifiers = ARRAY_SIZE(format_modifier1),
    .modifiers	 = format_modifier1,
    .min_width	 = 0,
    .min_height  = 0,
    .max_width	 = 4096,
    .max_height  = 4096,
    .rotation	 = DRM_MODE_ROTATE_0 |
             DRM_MODE_ROTATE_90 |
             DRM_MODE_ROTATE_180 |
             DRM_MODE_ROTATE_270 |
             DRM_MODE_REFLECT_X |
             DRM_MODE_REFLECT_Y,
    .blend_mode  = BIT(DRM_MODE_BLEND_PIXEL_NONE) |
             BIT(DRM_MODE_BLEND_PREMULTI) |
             BIT(DRM_MODE_BLEND_COVERAGE),
    .color_encoding = BIT(DRM_COLOR_YCBCR_BT709) |
              BIT(DRM_COLOR_YCBCR_BT2020),
    .degamma_size	= DEGAMMA_SIZE,
    .min_scale	 = FRAC_16_16(1, 3),
    .max_scale	 = FRAC_16_16(10, 1),
    .zpos		 = 1,
    .watermark	 = true,
    .color_mgmt  = true,
    .roi		 = true,
    },
    {
    .name		 = "Overlay_1",
    .id				= OVERLAY_PLANE_1,
    .type		 = DRM_PLANE_TYPE_OVERLAY,
    .num_formats = ARRAY_SIZE(primary_overlay_format1),
    .formats	 = primary_overlay_format1,
    .num_modifiers = ARRAY_SIZE(secondary_format_modifiers),
    .modifiers	 = secondary_format_modifiers,
    .min_width	 = 0,
    .min_height  = 0,
    .max_width	 = 4096,
    .max_height  = 4096,
    .rotation	 = 0,
    .blend_mode  = BIT(DRM_MODE_BLEND_PIXEL_NONE) |
             BIT(DRM_MODE_BLEND_PREMULTI) |
             BIT(DRM_MODE_BLEND_COVERAGE),
    .color_encoding = BIT(DRM_COLOR_YCBCR_BT709) |
              BIT(DRM_COLOR_YCBCR_BT2020),
    .degamma_size	= DEGAMMA_SIZE,
    .min_scale	 = DRM_PLANE_HELPER_NO_SCALING,
    .max_scale	 = DRM_PLANE_HELPER_NO_SCALING,
    .zpos		 = 2,
    .watermark	 = true,
    .color_mgmt  = true,
    .roi		 = true,
    },
    {
    .name		 = "Primary_1",
    .id				= PRIMARY_PLANE_1,
    .type		 = DRM_PLANE_TYPE_PRIMARY,
    .num_formats = ARRAY_SIZE(primary_overlay_format1),
    .formats	 = primary_overlay_format1,
    .num_modifiers = ARRAY_SIZE(format_modifier1),
    .modifiers	 = format_modifier1,
    .min_width	 = 0,
    .min_height  = 0,
    .max_width	 = 4096,
    .max_height  = 4096,
    .rotation	 = DRM_MODE_ROTATE_0 |
             DRM_MODE_ROTATE_90 |
             DRM_MODE_ROTATE_180 |
             DRM_MODE_ROTATE_270 |
             DRM_MODE_REFLECT_X |
             DRM_MODE_REFLECT_Y,
    .blend_mode  = BIT(DRM_MODE_BLEND_PIXEL_NONE) |
             BIT(DRM_MODE_BLEND_PREMULTI) |
             BIT(DRM_MODE_BLEND_COVERAGE),
    .color_encoding = BIT(DRM_COLOR_YCBCR_BT709) |
              BIT(DRM_COLOR_YCBCR_BT2020),
    .degamma_size	= DEGAMMA_SIZE,
    .min_scale	 = FRAC_16_16(1, 3),
    .max_scale	 = FRAC_16_16(10, 1),
    .zpos		 = 3,
    .watermark	 = true,
    .color_mgmt  = true,
    .roi		 = true,
    },
    {
    .name		 = "Overlay_2",
    .id				= OVERLAY_PLANE_2,
    .type		 = DRM_PLANE_TYPE_OVERLAY,
    .num_formats = ARRAY_SIZE(primary_overlay_format1),
    .formats	 = primary_overlay_format1,
    .num_modifiers = ARRAY_SIZE(format_modifier1),
    .modifiers	 = format_modifier1,
    .min_width	 = 0,
    .min_height  = 0,
    .max_width	 = 4096,
    .max_height  = 4096,
    .rotation	 = DRM_MODE_ROTATE_0 |
             DRM_MODE_ROTATE_90 |
             DRM_MODE_ROTATE_180 |
             DRM_MODE_ROTATE_270 |
             DRM_MODE_REFLECT_X |
             DRM_MODE_REFLECT_Y,
    .blend_mode  = BIT(DRM_MODE_BLEND_PIXEL_NONE) |
             BIT(DRM_MODE_BLEND_PREMULTI) |
             BIT(DRM_MODE_BLEND_COVERAGE),
    .color_encoding = BIT(DRM_COLOR_YCBCR_BT709) |
              BIT(DRM_COLOR_YCBCR_BT2020),
    .degamma_size	= DEGAMMA_SIZE,
    .min_scale	 = FRAC_16_16(1, 3),
    .max_scale	 = FRAC_16_16(10, 1),
    .zpos		 = 4,
    .watermark	 = true,
    .color_mgmt  = true,
    .roi		 = true,
    },
    {
    .name		 = "Overlay_3",
    .id				= OVERLAY_PLANE_3,
    .type		 = DRM_PLANE_TYPE_OVERLAY,
    .num_formats = ARRAY_SIZE(primary_overlay_format1),
    .formats	 = primary_overlay_format1,
    .num_modifiers = ARRAY_SIZE(secondary_format_modifiers),
    .modifiers	 = secondary_format_modifiers,
    .min_width	 = 0,
    .min_height  = 0,
    .max_width	 = 4096,
    .max_height  = 4096,
    .rotation	 = 0,
    .blend_mode  = BIT(DRM_MODE_BLEND_PIXEL_NONE) |
             BIT(DRM_MODE_BLEND_PREMULTI) |
             BIT(DRM_MODE_BLEND_COVERAGE),
    .color_encoding = BIT(DRM_COLOR_YCBCR_BT709) |
              BIT(DRM_COLOR_YCBCR_BT2020),
    .degamma_size	= DEGAMMA_SIZE,
    .min_scale	 = DRM_PLANE_HELPER_NO_SCALING,
    .max_scale	 = DRM_PLANE_HELPER_NO_SCALING,
    .zpos		 = 5,
    .watermark	 = true,
    .color_mgmt  = true,
    .roi		 = true,
    },
    {
    .name		 = "Cursor",
    .id				= CURSOR_PLANE_0,
    .type		 = DRM_PLANE_TYPE_CURSOR,
    .num_formats = ARRAY_SIZE(cursor_formats),
    .formats	 = cursor_formats,
    .num_modifiers = 0,
    .modifiers	 = NULL,
    .min_width	 = 32,
    .min_height  = 32,
    .max_width	 = 64,
    .max_height  = 64,
    .rotation	 = 0,
    .degamma_size = 0,
    .min_scale	 = DRM_PLANE_HELPER_NO_SCALING,
    .max_scale	 = DRM_PLANE_HELPER_NO_SCALING,
    .zpos		 = 255,
    .watermark	 = false,
    .color_mgmt  = false,
    .roi		 = false,
    },
    {
    .name		 = "Cursor_1",
    .id				= CURSOR_PLANE_1,
    .type		 = DRM_PLANE_TYPE_CURSOR,
    .num_formats = ARRAY_SIZE(cursor_formats),
    .formats	 = cursor_formats,
    .num_modifiers = 0,
    .modifiers	 = NULL,
    .min_width	 = 32,
    .min_height  = 32,
    .max_width	 = 64,
    .max_height  = 64,
    .rotation	 = 0,
    .degamma_size = 0,
    .min_scale	 = DRM_PLANE_HELPER_NO_SCALING,
    .max_scale	 = DRM_PLANE_HELPER_NO_SCALING,
    .zpos		 = 255,
    .watermark	 = false,
    .color_mgmt  = false,
    .roi		 = false,
    },
  },
```

TODO: Setup Display Pipeline / Commit Display Pipeline / Update Display Plane

# Setup Display Pipeline

TODO: Display Controller

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

TODO: Display Hardware


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

# Commit Display Pipeline

TODO: Display Controller

Commit Display Pipeline is here...

- [vs_dc_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1381-L1398), which calls...

- [dc_hw_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L2038-L2076)

Commit Display Pipeline [vs_dc_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1381-L1398) is called by [vs_crtc_atomic_flush](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_crtc.c#L320-L336)

Which is called by [drm_atomic_helper](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/drm_atomic_helper.c#L2445-L2570)

TODO: Display Hardware

Commit Display Hardware: [dc_hw_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L2038-L2076)
- Call [gamma_ex_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1548-L1574)
- Call [plane_ex_commit](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1768-L1863)
- Update Cursor
- Update QoS

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

# Update Display Plane

TODO: Display Controller

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

TODO: Display Hardware

Update Display Plane: [dc_hw_update_plane](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc_hw.c#L1368-L1399)
- Copy Framebuffer
- Copy Scale
- Copy Position
- Copy Blend

# DC8200 Framebuffer Driver

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

# What's Next

TODO

Prototype new driver in Zig

Slightly annoying that New Zig won't run on my Old Mac

[Fishwaldo suggests uboot](https://fosstodon.org/@Fishwaldo/110902984442385966)

[the panel is not a Jadard panel, whoever wrote the factory image just hacked a existing driver. The panel in PtV (and PT2) is a BOE TH101MB31IG002-28A](https://fosstodon.org/@Fishwaldo/110902984462760802)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/display2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/display2.md)

![JH7110 Display Subsystem Clock and Reset](https://lupyuen.github.io/images/display2-vout_clkrst18.png)

[_JH7110 Display Subsystem Clock and Reset_](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/clock_n_reset_display.html)

# Appendix: JH7110 Display Clock and Reset

TODO

[DOM VOUT CRG](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/dom_vout_crg.html)

## dc_bind

TODO

[__dc_bind__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L1421-L1573)

- dc_init
- vs_drm_iommu_attach_device: 

  Attach I/O MMU Device

- For Each Panel: vs_crtc_create: 

  Create Display Pipeline

- For Each Plane: vs_plane_create: 

  Create Display Plane

- vs_drm_update_pitch_alignment: 

  Update Pitch Alignment

- clk_disable_unprepare(vout_top_lcd): 

  Disable Clock vout_top_lcd (clk_dom_vout_top_lcd_clk?)

- dc8200 asrt: vs_dc8200_reset_assert: 

  Assert DC8200 Reset

- dc8200 clk disable: vs_dc_dc8200_clock_disable: 

  Disable DC8200 Clock

- vouttop clk disable: vs_dc_vouttop_clock_disable: 

  Disable Clock vouttop

- vout clk disable: vs_dc_clock_disable: 

  Disable DC Clock vout

## dc_init

TODO

[__dc_init__](https://github.com/starfive-tech/linux/blob/JH7110_VisionFive2_devel/drivers/gpu/drm/verisilicon/vs_dc.c#L644-L722)

- dc_vout_clk_enable: 

  Enable Clock dc_vout_clk

- vs_dc8200_reset_deassert: 

  Deassert DC8200 Reset

- clk_prepare_enable(vout_top_lcd): 

  Enable Clock vout_top_lcd

- vs_vout_reset_deassert: 

  Deassert vout_reset

- mystery code:

  ```c
  #ifdef CONFIG_DRM_I2C_NXP_TDA998X//tda998x-rgb2hdmi
    regmap_update_bits(dc->dss_regmap, 0x4, BIT(20), 1<<20);
  #endif

  #ifdef CONFIG_STARFIVE_DSI
    regmap_update_bits(dc->dss_regmap, 0x8, BIT(3), 1<<3);
  #endif
  ```

- dc_hw_init

# Appendix: JH7110 HDMI Controller

TODO

The HDMI Controller for JH7110 is [Inno HDMI 2.0 Transmitter For TSMC28HPC+](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/detail_info_display.html).

HDMI I2C Encoder in JH7110 is the [NXP Semiconductors TDA998X HDMI Encoder](https://doc-en.rvspace.org/VisionFive2/DG_Display/JH7110_SDK/kernel_menu_config_diplay.html)

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

# Appendix: JH7110 HDMI Testing

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

# Appendix: JH7110 LCD Panel Configuration

TODO

Also in the JH7110 Display Docs: How to connect an LCD Panel to JH7110.

JH7110's MIPI DSI Controller is [Cadence MIPI DSI v1.3.1 TX Controller IP (DSITX)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/ic_specification_lcd.html)...

![Cadence MIPI DSI v1.3.1 TX Controller IP (DSITX)](https://lupyuen.github.io/images/display2-ic_spec.png)

[(Source)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/ic_specification_lcd.html)

JH7110's MIPI DPHY Controller is [MIPI DPHY M31 (M31DPHYRX611TL028D_00151501)](https://doc-en.rvspace.org/VisionFive2/DG_LCD/JH7110_SDK/ic_specification_lcd.html)...

![MIPI DPHY M31 (M31DPHYRX611TL028D_00151501)](https://lupyuen.github.io/images/display2-MIPI_DPHY_M31.png)

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

# Appendix: DC8200 Virtual Display Driver

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

# Appendix: Inno HDMI Controller Driver

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

