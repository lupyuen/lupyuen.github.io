# Porting Apache NuttX RTOS to Avaota-A1 SBC (Allwinner A527 SoC)

📝 _9 Apr 2025_

![Avaota-A1 SBC (Allwinner A527 SoC)](https://lupyuen.org/images/avaota-title.jpg)

TODO

_Why are we doing this?_

- Anyone porting NuttX from __QEMU to Real SBC__? This walkthrough shall be mighty helpful!

TODO: Before Porting NuttX, we observe our SBC and its Natural Behaviour: How does it boot Linux?

I ported NuttX to a simpler A527 board, the Avaota-A1 SBC by PINE64 ($55): https://pine64.com/product/yuzuki-avaota-a1-single-board-computer-4gb-32gb/

Avaota-A1 SBC is Open Source Hardware (CERN OHL Licensed). PINE64 sells it today, maybe we'll see more manufacturers with the same design: https://github.com/AvaotaSBC/Avaota-A1

I think NuttX on Avaota-A1 (Allwinner A527) will be super interesting because:

(1) It's one of the first ports of Arm64 in NuttX Kernel Build (NXP i.MX93 might be another?)

(2) We'll run it as PR Test Bot for Validating Arm64 PRs

(3) PR Test Bot will be fully automated thanks to SDWire MicroSD Mux: https://lupyuen.org/articles/testbot3.html

Next article I'll explain how I ported NuttX from QEMU Arm64 (knsh) to Avaota-A1, completed within 24 hours.

Why?
Pr test bot
New soc
Kernel build
How to turn qemu into real hardware 
Why a mux will complete in 48 hours
Including sleep

Here's the story 

Build NuttX for 
Port NuttX to 

# What's Next

TODO

Special Thanks to [__My Sponsors__](https://lupyuen.org/articles/sponsor) for supporting my writing. Your support means so much to me 🙏

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for StarPro64 EIC7700X"__](https://github.com/lupyuen/nuttx-starpro64)

- [__My Other Project: "NuttX for Oz64 SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__Older Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/avaota.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/avaota.md)
