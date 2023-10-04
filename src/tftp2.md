# Strange Workaround for TFTP Timeout in U-Boot Bootloader (Star64 JH7110 SBC)

📝 _10 Oct 2023_

![Strange Workaround for TFTP Timeout in U-Boot Bootloader for Star64 JH7110 SBC](https://lupyuen.github.io/images/tftp2-title.jpg)

We're porting [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/release) to the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) Single-Board Computer. (Pic below)

(Powered by [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC, same as the VisionFive2 SBC)

But we're hitting frequent __TFTP Timeouts__ ("T" below) while booting NuttX over the Local Network.  Effective Transfer Rate is only __390 kbps__!

```text
Loading: 
. ##T #################################
. #######T ############################
. #####T ##############################
. ######################T #############
. ###################T T ##############
. 48.8 KiB/s
```

[(Source)](https://gist.github.com/lupyuen/b36278130fbd281d03fc20189de5485e)

This makes NuttX Testing super slow... Our SBC takes __4 minutes to boot__ over the Local Network!

[(Watch the Demo on YouTube)](https://youtu.be/MPBc2Qec6jo)

_How are we booting the SBC over the Network?_

We're booting our Star64 SBC over a Wired Ethernet Local Network with [__U-Boot Bootloader and TFTP__](https://lupyuen.github.io/articles/tftp).

(That's the Trivial File Transfer Protocol)

![Testing Apache NuttX RTOS on Star64 JH7110 SBC](https://lupyuen.github.io/images/release-star64.jpg)

_Can we fix the TFTP Timeouts?_

In this article we talk about the __Strange Workaround__ for the TFTP Timeouts...

- We __throttled our TFTP Server__ to send packets slower

  (Nope it doesn't help)

- We __reduced the TFTP Timeout__ in our server

  (Doesn't help either)

- But when we send every __TFTP Data Packet twice__...

  The problem mysteriously disappears!

So yes we have a (curiously unsatisfactory) solution.

Here's what we tested with Star64 SBC and U-Boot Bootloader...

![Send every TFTP Data Packet twice](https://lupyuen.github.io/images/tftp2-code.png)

# Send Everything Twice

_We hacked our TFTP Server to send every packet twice?_

Indeed! Because we can't configure any TFTP Server to send Data Packets twice.

TODO

From [rs-tftpd-timeout/src/worker.rs](https://github.com/lupyuen/rs-tftpd-timeout/blob/main/src/worker.rs#L232-L255)

```rust
// Transmit every Data Frame in the Data Window
// to the TFTP Client
fn send_window<T: Socket>(
  socket: &T,          // UDP Socket
  window: &Window,     // Data Window to be sent
  mut block_num: u16,  // Current Block Number
) -> Result<(), Box<dyn Error>> {

  // For every Data Frame in the Data Window...
  for frame in window.get_elements() {
    
    // Send the TFTP Data Packet
    socket.send(&Packet::Data {
      block_num,
      data: frame.to_vec(),
    })?;

    // Omitted: Increment the Block Number
```

Then we inserted this: [worker.rs](https://github.com/lupyuen/rs-tftpd-timeout/blob/main/src/worker.rs#L232-L255)

```rust
    // Right after sending the TFTP Data Packet...
    // Wait 1 millisecond
    let millis = std::time::Duration::from_millis(1);
    std::thread::sleep(millis);

    // Send the same TFTP Data Packet again.
    // Why does this work?
    socket.send(&Packet::Data {
      block_num,
      data: frame.to_vec(),
    })?;

    // Omitted: Increment the Block Number
```

Let's test this...

![Strange Workaround for TFTP Timeout in U-Boot Bootloader for Star64 JH7110 SBC](https://lupyuen.github.io/images/tftp2-title.jpg)

# No More Timeouts!

TODO

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

# Anyone Else Seeing This?

TODO

["Downloading with U-Boot's tftp randomly times out"](https://serverfault.com/questions/669340/downloading-with-u-boots-tftp-randomly-times-out)

According to [__martin-zs__](https://github.com/lupyuen/nuttx-star64/issues/2)...

> "Years ago I used to work in a mixed environment (Windows/Solaris/HP-US/Linux servers) and I noticed that __most windows machines send an insane amount of packets in triplicate__. UNIX would send everything once. This would make me wonder if the JH7110 SoC (or the licensed IP used) was only tested using windows machines."

> "My guess would be that if you setup a windows machine to be the tftp server, it would work - just because of the triple packets (mostly for UDP)."

[(Source)](https://github.com/lupyuen/nuttx-star64/issues/2)

Apparently Windows will send every TFTP Packet 3 times. Maybe that's why Star64 JH7110 U-Boot won't work well with Linux TFTP Servers?

# Throttle TFTP Server

_What if we throttle our TFTP Server to send packets slower?_

TODO: Doesn't work

# Reduce TFTP Timeout

_What if we reduce the TFTP Timeout in our server?_

TODO: Doesn't work

# TODO

TODO

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
