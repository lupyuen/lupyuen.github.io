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

This makes NuttX Testing super slow... Our SBC takes __4 minutes to boot__ over the Wired Local Network!

[(Watch the Demo on YouTube)](https://youtu.be/MPBc2Qec6jo)

_How are we booting the SBC over the Network?_

We're booting our Star64 SBC (pic below) over a Wired Ethernet Local Network with [__U-Boot Bootloader and TFTP__](https://lupyuen.github.io/articles/tftp).

(That's the Trivial File Transfer Protocol)

![Testing Apache NuttX RTOS on Star64 JH7110 SBC](https://lupyuen.github.io/images/release-star64.jpg)

_Can we fix the TFTP Timeouts?_

Yep! In this article we talk about the __Strange Workaround__ for the TFTP Timeouts...

- First we __throttled our TFTP Server__ to send packets slower

  (Which made it worse)

- Next we __reduced the TFTP Timeout__ in our server

  (Nope doesn't work)

- But when we send every __TFTP Data Packet twice__...

  The problem mysteriously disappears!

- We verified this with 2 TFTP Servers: __Linux and macOS__

So yes we have a (curiously unsatisfactory) solution.

Here's what we tested with Star64 SBC and U-Boot Bootloader...

![Send every TFTP Data Packet twice](https://lupyuen.github.io/images/tftp2-code.png)

# Send Everything Twice

_We hacked our TFTP Server to send every packet twice?_

Indeed! Because we can't configure any TFTP Server to send Data Packets twice.

Let's modify the [__`rs-tftpd`__](https://crates.io/crates/tftpd) TFTP Server. Here's the code that sends TFTP Data Packets: [rs-tftpd-timeout/src/worker.rs](https://github.com/lupyuen/rs-tftpd-timeout/blob/main/src/worker.rs#L232-L255)

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
      block_num,             // Current Block Number
      data: frame.to_vec(),  // Data Frame for the Packet
    })?;

    // Omitted: Increment the Block Number
```

To send every __TFTP Data Packet twice__, we inserted this: [worker.rs](https://github.com/lupyuen/rs-tftpd-timeout/blob/main/src/worker.rs#L232-L255)

```rust
    // Right after sending the TFTP Data Packet...
    // Wait 1 millisecond
    let millis = Duration::from_millis(1);
    thread::sleep(millis);

    // Send the same TFTP Data Packet again.
    // Why does this work?
    socket.send(&Packet::Data {
      block_num,             // Current Block Number
      data: frame.to_vec(),  // Data Frame for the Packet
    })?;

    // Omitted: Increment the Block Number
```

(We inserted a __1 millisecond delay__ between packets)

It's a simple mod, but it solves our TFTP Timeout!

_How do we run this?_

Follow these steps to start our __Modified TFTP Server__ on Linux and macOS...

```bash
## Download our Modified TFTP Server
git clone https://github.com/lupyuen/rs-tftpd-timeout
cd rs-tftpd-timeout

## Stop the xinetd + tftpd server
sudo service xinetd stop

## Might need this to set the Rust Toolchain for `sudo`
sudo $HOME/.cargo/bin/rustup default stable

## Start our Modified TFTP Server.
## Requires `sudo` because Port 69 is privileged.
## TODO: Change `/tftpboot` to your TFTP Folder
sudo --preserve-env \
  $HOME/.cargo/bin/cargo run -- \
  -i 0.0.0.0 \
  -p 69 \
  -d /tftpboot

## Or use `nohup` to keep it running continuously
## nohup sudo --preserve-env $HOME/.cargo/bin/cargo run -- -i 0.0.0.0 -p 69 -d /tftpboot

## Test our TFTP Server
## TODO: Change `192.168.x.x` to your TFTP Server Address
## TODO: Change `initrd` to a file in your TFTP Folder
curl -v \
  --output initrd \
  tftp://192.168.x.x/initrd
```

_Won't the extra Data Packet confuse the TFTP Client?_

That's perfectly OK because the __TFTP Block Number__ (sequence number) is encoded inside the UDP Data Packet.

The TFTP Client (like __`curl`__) will do the right thing and drop the __Duplicate Data Packets__...

```text
$ curl -v --output initrd tftp://192.168.31.10/initrd

* Connected to 192.168.31.10 () port 69 (#0)
* set timeouts for state 0; Total 300, retry 6 maxtry 50
* got option=(tsize) value=(9231360)
* tsize parsed from OACK (9231360)
* got option=(blksize) value=(512)
* blksize parsed from OACK (512) requested (512)
* got option=(timeout) value=(6)
* Connected for receive
* set timeouts for state 1; Total 3600, retry 72 maxtry 50
* Received last DATA packet block 1 again.
* Received last DATA packet block 2 again.
* Received last DATA packet block 3 again.
* Received last DATA packet block 4 again.
```

Let's test this with Star64 U-Boot...

![Strange Workaround for TFTP Timeout in U-Boot Bootloader for Star64 JH7110 SBC](https://lupyuen.github.io/images/tftp2-title.jpg)

# No More Timeouts!

_Does it work on Star64 with U-Boot Bootloader?_

Let's use __Raspberry Pi 4__ (32-bit Debian) as our TFTP Server...

1.  We run the standard __`xinetd + tftpd`__ on our Pi

    [(With this configuration)](https://community.arm.com/oss-platforms/w/docs/495/tftp-remote-network-kernel-using-u-boot)

1.  Then we switch to our __Modified TFTP Server__

    (From the previous section)

__Before Fixing:__ TFTP Transfer Rate (for `xinetd + tftpd`) is __390 kbps__ (with 6 timeouts)

```text
Filename 'initrd'. Loading: 
. ##T #################################
. #######T ############################
. #####T ##############################
. ######################T #############
. ###################T T ##############
. 48.8 KiB/s
Bytes transferred = 9,231,360
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/b36278130fbd281d03fc20189de5485e)

[(Watch the __Demo on YouTube__)](https://youtu.be/MPBc2Qec6jo)

__After Fixing:__ TFTP Transfer Rate (for our Modified TFTP Server) is __8 Mbps__ (with NO timeouts)

```text
Filename 'initrd'. Loading: 
. #####################################
. #####################################
. #####################################
. #####################################
. #####################################
. 1.1 MiB/s
Bytes transferred = 9,231,360
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/19ab2e16c0c2bb46175bcd8fba7116f2)

[(Watch the __Demo on YouTube__)](https://youtu.be/ABpi2ABln5o)

Yep it works: No more TFTP Timeouts!

And it's so much faster: NuttX boots in 20 seconds!

But why? We do a little research...

# Anyone Else Seeing This?

_Surely someone else might have the same problem?_

Our TFTP Timeout looks similar to this...

- [__"Downloading with U-Boot's tftp randomly times out"__](https://serverfault.com/questions/669340/downloading-with-u-boots-tftp-randomly-times-out)

I have a hunch that it's something specific to __U-Boot on JH7110 SoC__. And we probably can't reproduce it with Linux on JH7110.

_Sending Duplicate TFTP Packets... Feels horribly wrong!_

Yeah but we might have a precedent! According to [__martin-zs__](https://github.com/lupyuen/nuttx-star64/issues/2)...

> "Years ago I used to work in a mixed environment (Windows/Solaris/HP-US/Linux servers) and I noticed that __most windows machines send an insane amount of packets in triplicate__. UNIX would send everything once. This would make me wonder if the JH7110 SoC (or the licensed IP used) was only tested using windows machines."

> "My guess would be that if you setup a windows machine to be the tftp server, it would work - just because of the triple packets (mostly for UDP)."

[(Source)](https://github.com/lupyuen/nuttx-star64/issues/2)

Apparently Windows might send __every TFTP Packet 3 times__.

Maybe that's why Star64 JH7110 U-Boot won't work so well with Linux TFTP Servers?

_How will we track down the root cause?_

We might need __Wireshark__ to sniff the TFTP Packets.

And a __Windows TFTP Server__ to verify if it really sends every packet 3 times.

Before the sniffing, we do some sleuthing...

# Reduce TFTP Timeout

_Why does every TFTP Timeout pause for 5 seconds?_

[(Watch the __Demo on YouTube__)](https://youtu.be/MPBc2Qec6jo)

The 5-second Timeout Duration is computed here: [worker.rs](https://github.com/lupyuen/rs-tftpd-timeout/blob/80730178595ad550871fec72148d4f3e723b650a/src/worker.rs#L132-L141)

```rust
// Send the file to TFTP Client
fn send_file(self, file: File) -> Result<(), Box<dyn Error>> {
  ...
  // Compute the TFTP Timeout
  let mut time = Instant::now() - (
    self.timeout +  // 5 seconds
    TIMEOUT_BUFFER  // 1 second
  );
```

_What if we reduce the Timeout Duration?_

When we change the code above to reduce the Timeout Duration, __TFTP stops working__ altogether...

The TFTP Client (U-Boot) keeps timing out without transferring any data.

We try something else...

# Throttle TFTP Server

_What if we throttle our TFTP Server to send packets slower?_

We tried to slow down the TFTP Server: When we hit any Resends and Timeouts, we __increase the delay__ between packets.

Here's the code that waits a bit (1 millisecond initially) between packets: [worker.rs](https://github.com/lupyuen/rs-tftpd-timeout/blob/d7a699f7f206121ba392dd8f864f2bc386dfea27/src/worker.rs#L243-L267)

```rust
// Omitted: Send the TFTP Data Packet

// Wait a while before sending the next packet
static mut DELAY_MS: u64 = 1;
let millis = Duration::from_millis(DELAY_MS);
thread::sleep(millis);
```

Then we inserted the logic to check if we are __resending the same packet__: [worker.rs](https://github.com/lupyuen/rs-tftpd-timeout/blob/d7a699f7f206121ba392dd8f864f2bc386dfea27/src/worker.rs#L243-L267)

```rust
// Is this is a resend?
// Compare with the last Block Number
static mut LAST_BLOCK_NUM: u16 = 0;            
if block_num > 1 && block_num <= LAST_BLOCK_NUM {

  // If it's a resend: Double the delay
  println!("*** send_window RESEND: block_num={}", block_num);
  DELAY_MS = DELAY_MS * 2;
}

// Remember the last Block Number
LAST_BLOCK_NUM  = block_num;
```

If this is a Resend, we __double the delay__ between packets.

Also we __check for Timeout__ by comparing Timestamps: [worker.rs](https://github.com/lupyuen/rs-tftpd-timeout/blob/d7a699f7f206121ba392dd8f864f2bc386dfea27/src/worker.rs#L243-L267)

```rust
// Is this is a delayed send?
// Compare with the last Timestamp
static mut LAST_TIMESTAMP: ... = ... Instant::now();
let diff_time = Instant::now() - *LAST_TIMESTAMP;
if block_num > 1 && diff_time > Duration::from_millis(1000) {

  // If it's delayed by 1 sec: Double the delay
  println!("+++ send_window DELAY: block_num={}", block_num);
  DELAY_MS = DELAY_MS * 2;
}

// Remember the last Timestamp
*LAST_TIMESTAMP = Instant::now();
```

If this is a Timeout, we __double the delay__ between packets.

_Does it work?_

Nope, it got worse. We still see Timeouts in spite of the extra delay between packets.

And the Data Transfer becomes terribly slow (because of the longer and longer delays)...

```text
Sending initrd
+++ send_window DELAY: block_num=15
+++ send_window DELAY: block_num=2366
+++ send_window DELAY: block_num=2755
+++ send_window DELAY: block_num=5012
Sent initrd
```

[(See the __Complete Log__)](https://github.com/lupyuen/rs-tftpd-timeout/blob/d7a699f7f206121ba392dd8f864f2bc386dfea27/src/worker.rs#L275-L295)

[(See the __Resend Log__)](https://github.com/lupyuen/rs-tftpd-timeout/blob/52ee5a9b3ddcb4972578141c0479ee172c46e6c0/src/worker.rs#L302-L308)

Thus throttling our TFTP Server doesn't help.

![Booting Star64 JH7110 SBC over TFTP](https://lupyuen.github.io/images/tftp2-flow.jpg)

# All Things Considered

_We sure this isn't a Hardware Problem at our TFTP Server?_

_Or a Network Problem?_

We tested 2 TFTP Servers: __Raspberry Pi 4__ (32-bit Linux) and __MacBook Pro__ (x64 macOS)...

| TFTP Server | xinetd + <br> tftpd | Original <br> rs-tftpd | Modified <br> rs-tftpd |
|:------------|:--------------:|:-----------------:|:-----------------:|
| __Linux__ | _Some Timeouts_ | | __NO Timeouts__ |
| __macOS__ | | _Some Timeouts_ | __NO Timeouts__ |

Thus we're sure that it's not a Hardware or OS Problem at the TFTP Server.

Then we __downloaded a 9 MB file__ from Raspberry Pi to MacBook over TFTP on Wired Ethernet...

```text
## Before Fixing TFTP Server: 19 Mbps (xinetd + tftpd)
$ curl --output initrd tftp://192.168.31.10/initrd

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 9015k    0 9015k    0     0  2374k      0 --:--:--  0:00:03 --:--:-- 2374k

## After Fixing TFTP Server: 3.3 Mbps (Modified rs-tftpd)
$ curl --output initrd tftp://192.168.31.10/initrd

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 9015k  100 9015k    0     0   411k      0  0:00:21  0:00:21 --:--:--  411k
```

Our Wired Ethernet Network looks hunky dory, no problems here.

(Our Modified TFTP Server is slower because of the 1 millisecond delay between packets. And we sent every packet twice)

_So this TFTP Timeout seems specific to JH7110 U-Boot?_

Yeah. Maybe U-Boot Bootloader on Star64 JH7110 missed some Incoming UDP Packets?

# What's Next

Porting NuttX to Star64 JH7110 becomes so much faster now. Stay tuned for updates!

[(Like the upcoming __NuttX I2C Driver for JH7110__)](https://lupyuen.github.io/articles/display3#appendix-jh7110-display-driver)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/tftp2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/tftp2.md)
