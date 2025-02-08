# Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)

📝 _28 Feb 2025_

![Test Bot for Pull Requests ... Tested on Real Hardware (Apache NuttX RTOS / Oz64 SG2000 RISC-V SBC)](https://lupyuen.org/images/testbot-title.jpg)

We're [__Making Things Better__](https://lists.apache.org/thread/mn4l1tmr6fj46o2y9vvrmfcrgyo48s5d) (and making better things) with [__Apache NuttX RTOS__](TODO).

Our new __Test Bot for Pull Requests__ will allow a [__Pull Request Comment__](https://github.com/apache/nuttx/pull/15756#issuecomment-2641277894) to trigger a __NuttX Build + Test__ on Real Hardware. For example, this PR Comment...

```bash
@nuttxpr test oz64:nsh
```

Will trigger our PR Test Bot to download the PR Code and test it on [__Oz64 SG2000 RISC-V SBC__](TODO). (Pic above)

Super helpful for __Testing Pull Requests__ before Merging. But might have [__Security Implications__](https://github.com/apache/nuttx/issues/15731#issuecomment-2628647886). (We'll come back to this)

![NuttX Bot for Building and Testing Pull Requests](https://lupyuen.org/images/rewind-bot3.jpg)

_(Thanks to PINE64 for sponsoring the Oz64 SBC)_

# What's Next

Special Thanks to __Mr Gregory Nutt__ for your guidance and kindness. I'm also grateful to [__My Sponsors__](https://lupyuen.org/articles/sponsor), for supporting my writing. 

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/testbot.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/testbot.md)
