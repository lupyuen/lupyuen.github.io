# NuttX RTOS for PinePhone: Framebuffer

📝 _7 Jan 2023_

![TODO](https://lupyuen.github.io/images/fb-title.jpg)

TODO: How NuttX Apps call the NuttX Framebuffer Interface to render graphics... And what's inside the Framebuffer Driver for Pine64 PinePhone

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) now boots on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)

# TODO

TODO

[fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L541-L562)

```c
static void render_grey(struct fb_state_s *state) {
  // Fill entire framebuffer with grey
  memset(
    state->pinfo.fbmem,
    0x80,
    state->pinfo.fblen
  );

#ifdef CONFIG_FB_UPDATE
  // Update the framebuffer
  struct fb_area_s area =
  {
    .x = 0,
    .y = 0,
    .w = state->pinfo.xres_virtual,
    .h = state->pinfo.yres_virtual
  };
  int ret = ioctl(state->fd, FBIO_UPDATE,
                  (unsigned long)((uintptr_t)&area));
  DEBUGASSERT(ret == OK);
#endif
}
```

TODO

[fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L564-L601)

```c
static void render_blocks(struct fb_state_s *state) {
  // Fill framebuffer with Blue, Green and Red Blocks
  uint32_t *fbmem = state->pinfo.fbmem;
  const size_t fblen = state->pinfo.fblen / 4;  // 4 bytes per pixel

  // For every pixel...
  for (int i = 0; i < fblen; i++) {

    // Colors are in XRGB 8888 format
    if (i < fblen / 4) {
      // Blue for top quarter.
      // RGB24_BLUE is 0x0000 00FF
      fbmem[i] = RGB24_BLUE;
    } else if (i < fblen / 2) {
      // Green for next quarter.
      // RGB24_GREEN is 0x0000 FF00
      fbmem[i] = RGB24_GREEN;
    } else {
      // Red for lower half.
      // RGB24_RED is 0x00FF 0000
      fbmem[i] = RGB24_RED;
    }
  }

#ifdef CONFIG_FB_UPDATE
  // Update the framebuffer
  struct fb_area_s area =
  {
    .x = 0,
    .y = 0,
    .w = state->pinfo.xres_virtual,
    .h = state->pinfo.yres_virtual
  };
  int ret = ioctl(state->fd, FBIO_UPDATE,
                  (unsigned long)((uintptr_t)&area));
  DEBUGASSERT(ret == OK);
#endif
}
```

TODO

[fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L603-L651)

```c
static void render_circle(struct fb_state_s *state) {
  // Fill framebuffer with Green Circle
  uint32_t *fbmem = state->pinfo.fbmem;
  const size_t fblen = state->pinfo.fblen / 4;  // 4 bytes per pixel
  const uint32_t width = state->pinfo.xres_virtual;
  const uint32_t height = state->pinfo.yres_virtual;

  // For every pixel row...
  for (int y = 0; y < height; y++) {

    // For every pixel column...
    for (int x = 0; x < width; x++) {

      // Get pixel index
      const int p = (y * width) + x;
      DEBUGASSERT(p < fblen);

      // Shift coordinates so that centre of screen is (0,0)
      const int half_width  = width  / 2;
      const int half_height = height / 2;
      const int x_shift = x - half_width;
      const int y_shift = y - half_height;

      // If x^2 + y^2 < radius^2, set the pixel to Green.
      // Colors are in XRGB 8888 format.
      if (x_shift*x_shift + y_shift*y_shift < half_width*half_width) {
        // RGB24_GREEN is 0x0000 FF00
        fbmem[p] = RGB24_GREEN;
      } else {  // Otherwise set to Transparent Black
        // RGB24_BLACK is 0x0000 0000
        fbmem[p] = RGB24_BLACK;
      }
    }
  }

#ifdef CONFIG_FB_UPDATE
  // Update the framebuffer
  struct fb_area_s area =
  {
    .x = 0,
    .y = 0,
    .w = state->pinfo.xres_virtual,
    .h = state->pinfo.yres_virtual
  };
  int ret = ioctl(state->fd, FBIO_UPDATE,
                  (unsigned long)((uintptr_t)&area));
  DEBUGASSERT(ret == OK);
#endif
}
```

# What's Next

TODO

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

-   [__"NuttX RTOS for PinePhone: MIPI Display Serial Interface"__](https://lupyuen.github.io/articles/dsi3)

-   [__"NuttX RTOS for PinePhone: Display Engine"__](https://lupyuen.github.io/articles/de3)

-   [__"NuttX RTOS for PinePhone: LCD Panel"__](https://lupyuen.github.io/articles/lcd)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/fb.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/fb.md)
