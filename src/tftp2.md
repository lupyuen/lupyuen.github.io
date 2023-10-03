# Strange Workaround for TFTP Timeout in U-Boot Bootloader (Star64 JH7110 SBC)

📝 _10 Oct 2023_

![TODO](https://lupyuen.github.io/images/tftp2-title.jpg)

TODO

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/release) (or Linux) can get _painfully tedious_ on a Single-Board Computer...

[__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64)

(Powered by [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

# Strange Workaround for TFTP Timeout in U-Boot Bootloader

TODO

["Downloading with U-Boot's tftp randomly times out"](https://serverfault.com/questions/669340/downloading-with-u-boots-tftp-randomly-times-out)

Why does TFTP time out so often on our SBC? Is it because our TFTP Server sends packets too quickly to our SBC?

Frequent TFTP Timeouts ("T" below) are affecting our NuttX Testing on Star64 JH7110 SBC.  Effective transfer rate is only 430 kbps!

```text
Loading: . ##############T ###################################################
. ####################T #########T ####################################
. 53.7 KiB/s
```

[(Source)](https://gist.github.com/lupyuen/9bdb1f5478318631d0480f03f6041d83#file-jh7110-nuttx-math-log-L140-L173)

Let's try something: We send every TFTP Packet twice.

From https://github.com/lupyuen/rs-tftpd-timeout/blob/main/src/worker.rs#L232-L255

```rust
fn send_window<T: Socket>(
  socket: &T,
  window: &Window,
  mut block_num: u16,
) -> Result<(), Box<dyn Error>> {
  // For Every Frame...
  for frame in window.get_elements() {
    
    // Send the TFTP Packet
    socket.send(&Packet::Data {
      block_num,
      data: frame.to_vec(),
    })?;

    // Wait 1 millisecond
    static mut DELAY_MS: u64 = 1;
    let millis = std::time::Duration::from_millis(DELAY_MS);
    std::thread::sleep(millis);

    // Send the same TFTP Packet again
    // Why does this work?
    socket.send(&Packet::Data {
      block_num,
      data: frame.to_vec(),
    })?;
```

Let's test this...

__Before Fixing:__ TFTP Transfer Rate is 48.8 KiB/s (with 6 timeouts)

[(See the log: xinetd + tftpd on Raspberry Pi 4 32-bit)](https://gist.github.com/lupyuen/b36278130fbd281d03fc20189de5485e)

[(Watch the Demo on YouTube)](https://youtu.be/MPBc2Qec6jo)

[(Based on this configuration)](https://community.arm.com/oss-platforms/w/docs/495/tftp-remote-network-kernel-using-u-boot)

__After Fixing:__ TFTP Transfer Rate is 1.1 MiB/s (with NO timeouts)

[(See the log: rs-tftpd-timeout on Raspberry Pi 4 32-bit)](https://gist.github.com/lupyuen/19ab2e16c0c2bb46175bcd8fba7116f2)

[(Watch the Demo on YouTube)](https://youtu.be/ABpi2ABln5o)

[(Based on rs-tftpd-timeout)](https://github.com/lupyuen/rs-tftpd-timeout/blob/main/src/worker.rs#L232-L255)

Yep it works! No more TFTP Timeouts!

(Tested on 32-bit Raspberry Pi 4 and on macOS x64)

TODO: Why does it work? Dropped UDP Packets? We should check with Wireshark

TODO: What if we throttle our TFTP Server to send packets slower? Nope doesn't help

TODO: What if we we reduce the timeout? Nope doesn't work

_Does this problem happen for devices other than Star64 JH7110?_

Nope this TFTP Timeout seems specific to Star64 JH7110. We downloaded a 9 MB file from Pi to macOS over TFTP on Wired Ethernet...

```text
# Before Fixing TFTP Server: 19 Mbps
→ curl --output initrd tftp://192.168.31.10/initrd

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 9015k    0 9015k    0     0  2374k      0 --:--:--  0:00:03 --:--:-- 2374k

# After Fixing TFTP Server: 3.3 Mbps
→ curl --output initrd tftp://192.168.31.10/initrd

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 9015k  100 9015k    0     0   411k      0  0:00:21  0:00:21 --:--:--  411k
```

The fixed TFTP Server is slower because of the 1 millisecond delay between packets. And we sent every packet twice.

So maybe U-Boot Bootloader on Star64 JH7110 is too slow to catch all the TFTP Packets?

# What's Next

TODO

Porting NuttX to Star64 JH7110 becomes so much faster. Stay tuned for updates!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tftp2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tftp2.md)
