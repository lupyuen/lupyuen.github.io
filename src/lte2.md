# NuttX RTOS for PinePhone: Phone Calls and Text Messages

📝 _5 May 2023_

![Apache NuttX RTOS makes a Phone Call from Pine64 PinePhone](https://lupyuen.github.io/images/lte2-title.jpg)

What makes [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) a phone? Because it will make __Phone Calls__ and send __Text Messages__!

We're porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) to PinePhone. Today let's turn __NuttX into a Feature Phone__...

-   Outgoing and Incoming __Phone Calls__ over 4G

-   Send and receive __SMS Text Messages__

-   Why we prefer __PDU Text Messages__ for SMS

-   Programming the __4G LTE Modem__ with Apache NuttX RTOS

-   Doing all these over __UART vs USB__

We begin with the 4G LTE Modem inside PinePhone...

![Quectel EG25-G LTE Modem](https://lupyuen.github.io/images/usb2-modem.jpg)

[_Quectel EG25-G LTE Modem_](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_LTE_Standard_Specification_V1.3.pdf)

# Quectel EG25-G LTE Modem

_What's this LTE Modem?_

Inside PinePhone is the [__Quectel EG25-G LTE Modem__](https://wiki.pine64.org/index.php/PinePhone#Modem) for [__4G LTE__](https://en.wikipedia.org/wiki/LTE_(telecommunication)) Voice Calls, SMS and Mobile Data, plus GPS (pic above)...

-   [__Quectel EG25-G Datasheet__](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_LTE_Standard_Specification_V1.3.pdf)

-   [__EG25-G Hardware Design__](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_Hardware_Design_V1.4.pdf)

To control the LTE Modem, we send __AT Commands__...

-   [__EG25-G AT Commands__](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

-   [__EG25-G GNSS__](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_GNSS_Application_Note_V1.3.pdf)

-   [__Get Started with AT Commands__](https://www.twilio.com/docs/iot/supersim/works-with-super-sim/quectel-eg25-g)

So to dial the number __`1711`__, we send this AT Command...

```text
ATD1711;
```

The LTE Modem has similar AT Commands for SMS and Mobile Data.

[(EG25-G runs on __Qualcomm MDM 9607__ with a Cortex-A7 CPU inside)](https://xnux.eu/devices/feature/modem-pp.html#toc-modem-on-pinephone)

_How to send the AT Commands to LTE Modem?_

The LTE Modem accepts __AT Commands__ in two ways (pic below)...

-   Via the __UART Port (Serial)__

    Which is Slower: Up to 921.6 kbps

-   Via the __USB Port (USB Serial)__

    Which is Faster: Up to 480 Mbps

So if we're sending and receiving __lots of 4G Mobile Data__, USB is the better way.

Today we'll talk about the __UART Interface__, which is sufficient for building a Feature Phone on NuttX.

Let's power up the LTE Modem in PinePhone...

![Note: Power Key and Reset are High-Low Inverted for PinePhone](https://lupyuen.github.io/images/lte-power2.png)

[_Note: Power Key and Reset are __High-Low Inverted__ for PinePhone_](https://lupyuen.github.io/articles/lte#power-on-lte-modem)

# Start LTE Modem

_Before sending AT Commands..._

_How will we power up the LTE Modem?_

In the previous article we spoke about __starting the LTE Modem__ with NuttX (pic above)...

-   [__"Power On LTE Modem"__](https://lupyuen.github.io/articles/lte#power-on-lte-modem)

-   [__"Power Up wth NuttX"__](https://lupyuen.github.io/articles/lte#power-up-wth-nuttx)

-   [__"Is LTE Modem Up?"__](https://lupyuen.github.io/articles/lte#is-lte-modem-up)

Which we have implemented in NuttX as [__pinephone_modem_init__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/bb1ef61d6dbb5309a1e92583caaf81513308320a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L226-L356).

We see this at __NuttX Startup__...

```text
Starting kernel...
Enable UART3 on PD0
Enable UART3 on PD1
Set PWR_BAT (PL7) to High
Set RESET_N (PC4) to Low
Set AP-READY (PH7) to Low to wake up modem
Set DTR (PB2) to Low to wake up modem
Set PWRKEY (PB3) to High
Wait 600 ms
Set PWRKEY (PB3) to Low
Set W_DISABLE (PH8) to High
Status=1
...
Status=0

NuttShell (NSH) NuttX-12.0.3
nsh> 
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L473-L562)

Which says that PinePhone's LTE Modem is up and __accessible at Port UART3__!

Let's send some AT Commands to UART3...

![NuttX sends AT Commands to LTE Modem](https://lupyuen.github.io/images/lte-run3a.png)

[_NuttX sends AT Commands to LTE Modem_](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L562-L630)

# Send AT Commands

_LTE Modem has started successfully at UART3..._

_How will we send AT Commands to the modem?_

This is how we __send an AT Command__ to the LTE Modem over UART3: [hello_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L52-L75)

```c
// Open /dev/ttyS1 (UART3)
int fd = open("/dev/ttyS1", O_RDWR);
printf("Open /dev/ttyS1: fd=%d\n", fd);
assert(fd > 0);

// Repeat 5 times: Write command and read response
for (int i = 0; i < 5; i++) {

  // Write command
  const char cmd[] = "AT\r";
  ssize_t nbytes = write(fd, cmd, strlen(cmd));
  printf("Write command: nbytes=%ld\n%s\n", nbytes, cmd);
  assert(nbytes == strlen(cmd));

  // Read response
  static char buf[1024];
  nbytes = read(fd, buf, sizeof(buf) - 1);
  if (nbytes >= 0) { buf[nbytes] = 0; }
  else { buf[0] = 0; }
  printf("Response: nbytes=%ld\n%s\n", nbytes, buf);

  // Wait a while
  sleep(2);
}

// Close the device
close(fd);
```

The NuttX App above sends the command "__`AT`__" to the LTE Modem over UART3. (5 times)

Watch what happens when we run it...

Our NuttX App sends command "__`AT`__" to the LTE Modem over UART3...

```text
Open /dev/ttyS1
Write command: AT\r
```

No response! At startup, the LTE Modem might take [__30 seconds__](https://lupyuen.github.io/articles/lte#is-lte-modem-up) to become operational. Then this appears...

```text
Response:
RDY
```

"__`RDY`__" means that the LTE Modem is ready for AT Commands!

[(EG25-G AT Commands, Page 297)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

Our NuttX App sends command "__`AT`__" again...

```text
Write command: AT\r
Response:
+CFUN: 1
+CPIN: READY
+QUSIM: 1
+QIND: SMS DONE
+QIND: PB DONE
```

LTE Modem replies...

- "__`+CFUN: 1`__"

  This says that the LTE Modem is fully operational

  [(EG25-G AT Commands, Page 33)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+CPIN: READY`__"

  4G SIM Card is all ready, no PIN needed

  [(EG25-G AT Commands, Page 60)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+QUSIM: 1`__"

  Identifies SIM card type

  [(Says here)](https://forums.quectel.com/t/what-means-qusim-1/2526/2)

- "__`+QIND: SMS DONE`__"

  SMS is ready

  [(EG25-G AT Commands, Page 297)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+QIND: PB DONE`__"

  Phonebook is ready (for SIM Contacts)

  [(EG25-G AT Commands, Page 297)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

Our NuttX App sends command "__`AT`__" once more...

```text
Write command: AT\r
Response:
AT
OK
```

LTE Modem echoes our command "__`AT`__"...

And responds to our command with  "__`OK`__".

Which means that our LTE Modem is running AT Commands all OK!

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L562-L630)

_The actual log looks kinda messy..._

Yeah we'll talk about the proper AT Modem API in a while.

First let's check the network and make some phone calls...

# Check the LTE Network

_Before making a Phone Call..._

_How to check if the 4G LTE Network is OK?_

To check if the LTE Modem has connected successfully to the 4G LTE Network, we send these AT Commands...

- "__`AT+CREG?`__"

  Check Network Status

  [(EG25-G AT Commands, Page 77)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`AT+COPS?`__"

  Get Network Operator

  [(EG25-G AT Commands, Page 75)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

This is how we do it: [hello_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L81-L122)

```c
// Check the Network Status: AT+CREG?
const char cmd[] = "AT+CREG?\r";
write(fd, cmd, strlen(cmd));

// Read response
static char buf[1024];
nbytes = read(fd, buf, sizeof(buf) - 1);
if (nbytes >= 0) { buf[nbytes] = 0; }
else { buf[0] = 0; }
printf("Response: nbytes=%ld\n%s\n", nbytes, buf);

// Wait 2 seconds
sleep(2);

// Get the Network Operator
const char cmd[] = "AT+COPS?\r";
write(fd, cmd, strlen(cmd));

// Omitted: Read response and wait 2 seconds
```

And here's the output (pic below)...

```text
NuttShell (NSH) NuttX-12.0.3
nsh> hello

// Check Network Status
Command: AT+CREG?
Response:
+CREG: 0,1
// Network is ready

// Get Network Operator (SGP-M1)
Command: AT+COPS?
Response:
+COPS: 0,0,"SGP-M1",7
```

"__`+CREG: 0,1`__" says that the 4G LTE Network is ready.

"__`SGP-M1`__" is the name of our 4G LTE Network Operator.

We're all set to make some calls!

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L562-L737)

![NuttX makes a Phone Call from PinePhone](https://lupyuen.github.io/images/lte2-title.jpg)

[_NuttX makes a Phone Call from PinePhone_](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L683-L735)

# Outgoing Phone Call

This is how we dial a Phone Number to make an __Outgoing Phone Call__: [dial_number](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L343-L432)

```c
// Get Range of PCM Parameters for Digital Audio
const char cmd[] = "AT+QDAI=?\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response and wait 2 seconds

// Get Current PCM Configuration for Digital Audio
const char cmd[] = "AT+QDAI?\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response and wait 2 seconds
```

We begin by configuring the __PCM Digital Audio__ for our Voice Call.

(More about "__`AT+QDAI`__" in a while)

Suppose we're dialing the (fictitious) number "__`+1234567890`__".

We send the command "__`ATD+1234567890;`__"...

```c
// Phone Number to dial
#define PHONE_NUMBER "+1234567890"

// Make Outgoing Phone Call
const char cmd[] = 
  "ATD"
  PHONE_NUMBER
  ";\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response
```

[(EG25-G AT Commands, Page 114)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

We wait 20 seconds...

```c
// Wait 20 seconds for receiver to answer
sleep(20);
```

Finally we hang up the call with "__`ATH`__"...

```c
// Hang up Phone Call
const char cmd[] = "ATH\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response and wait 2 seconds
```

[(EG25-G AT Commands, Page 116)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

Here's the output (pic above)...

```text
// Get Range of PCM Parameters for Digital Audio
Command: AT+QDAI=?
Response: +QDAI: (1-4),(0,1),(0,1),(0-5),(0-2),(0,1)(1)(1-16)

// Get Current PCM Configuration for Digital Audio
Command: AT+QDAI?
Response: +QDAI: 1,1,0,1,0,0,1,1

// Make Outgoing Phone Call
Command: ATD+1234567890;
Response:
OK

// Receiver has hung up
Response:
NO CARRIER

// After 20 seconds, hang up Phone Call
Command: ATH
Response: OK
```

And the phone rings for the called Phone Number! (Pic above)

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L562-L737)

_But how will we talk to the called Phone Number?_

Aha! That's why we need the "__`AT+QDAI`__" commands, for the __PCM Digital Audio__ setup. We're still working on it...

- [__"PCM Digital Audio"__](https://lupyuen.github.io/articles/lte2#appendix-pcm-digital-audio)

Now we send an SMS Text Message...

![NuttX sends an SMS in Text Mode](https://lupyuen.github.io/images/lte2-sms.jpg)

[_NuttX sends an SMS in Text Mode_](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L622-L659)

# Send SMS in Text Mode

To send an __SMS Message__ (in Text Mode), use these AT Commands...

1.  "__`AT+CMGF=1`__"

    Select Text Mode for SMS (instead of PDU Mode)

    [(EG25-G AT Commands, Page 146)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

1.  "__`AT+CSCS="GSM"`__"

    Select GSM Character Set (instead of UCS2)

    [(EG25-G AT Commands, Page 25)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

1.  "__`AT+CMGS="+1234567890"`__"

    Send an SMS to the (imaginary) Phone Number "__`+1234567890`__"

    (Also works without country code, like "__`234567890`__")

    [(EG25-G AT Commands, Page 159)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

1.  __Wait for Modem__ to respond with "__`>`__"

1.  __Enter SMS Message__ in Text Format, terminate with Ctrl-Z...

    ```text
    Hello from Apache NuttX RTOS on PinePhone!<Ctrl-Z>
    ```

1.  Modem responds with the __Message ID__...

    ```text
    +CMGS: 22
    ```

    [(EG25-G AT Commands, Page 159)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

This is how we send an SMS with NuttX: [send_sms_text](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L162-L253)

```c
// Select Text Mode for SMS (instead of PDU Mode)
const char cmd[] = "AT+CMGF=1\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response and wait 2 seconds

// Select GSM Character Set (instead of UCS2)
const char cmd[] = "AT+CSCS=\"GSM\"\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response and wait 2 seconds

// Phone Number that will receive the SMS.
// Also works without country code, like "234567890"
#define PHONE_NUMBER "+1234567890"

// Send an SMS to the (imaginary) Phone Number "+1234567890"
const char cmd[] = 
  "AT+CMGS=\""
  PHONE_NUMBER
  "\"\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response and wait 2 seconds

// Wait for Modem to respond with ">"
for (;;) {
  // Read response
  static char buf[1024];
  ssize_t nbytes = read(fd, buf, sizeof(buf) - 1);
  if (nbytes >= 0) { buf[nbytes] = 0; }
  else { buf[0] = 0; }
  printf("Response: nbytes=%ld\n%s\n", nbytes, buf);

  // Stop if we find ">"
  if (strchr(buf, '>') != NULL) { break; }
}

// Enter SMS Message in Text Format, terminate with Ctrl-Z
const char cmd[] = 
  "Hello from Apache NuttX RTOS on PinePhone!"
  "\x1A";  // End of Message (Ctrl-Z)
write(fd, cmd, strlen(cmd));

// Omitted: Read response and wait 2 seconds
// Modem responds with the Message ID
```

Here's the log (pic above)...

```text
// Select Text Mode for SMS (instead of PDU Mode)
Command: AT+CMGF=1
Response: OK

// Select GSM Character Set (instead of UCS2)
Command: AT+CSCS="GSM"
Response: OK

// Send an SMS to the (imaginary) Phone Number "+1234567890"
// Also works without country code, like "234567890"
Command:
AT+CMGS="+1234567890"

// Wait for Modem to respond with ">"
Response:
> 

// Enter SMS Message in Text Format, terminate with Ctrl-Z
Command:
Hello from Apache NuttX RTOS on PinePhone!<Ctrl-Z>

// Modem responds with the Message ID
Response:
+CMGS: 22
OK
```

And the SMS Message will be sent to the Phone Number! (Pic above)

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L622-L659)

_What if we get Error 350?_

```text
+CMS ERROR: 350
```

This means that the Telco's __SMS Centre has rejected__ our SMS Message.

Check that the SMS Centre is correct [(like this)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/b291696fcaaee1700161796ac8a8320842ebee3d/examples/hello/hello_main.c#L127-L145)...

```text
// Get SMS Centre
Command: AT+CSCA?
Response:
+CSCA: "+6587614701",145
```

Also check that the SIM Card works OK on another phone.

(I had a peculiar SIM Card that blocks Outgoing SMS, but allows Outgoing Phone Calls)

# Send SMS in PDU Mode

_Sending an SMS Message looks easy!_

Ah but there's another (preferred and precise) way: __PDU Mode__.

[(Which means __Protocol Data Unit__)](https://en.wikipedia.org/wiki/GSM_03.40)

In PDU Mode, we encode the SMS Messages as __Hexadecimal Numbers__. These are the official docs...

- [__Quectel GSM AT Commands Application Note__](https://www.cika.com/soporte/Information/GSMmodules/Quectel/AppNotes/Quectel_GSM_ATC_Application_Note.pdf)

  (Section 9.3.2 "Send SMS in PDU mode", Page 26)

- [__ETSI GSM 07.05 Spec__](https://www.etsi.org/deliver/etsi_gts/07/0705/05.01.00_60/gsmts_0705v050100p.pdf)

  (For AT Commands)

- [__ETSI GSM 03.40 Spec__](https://en.wikipedia.org/wiki/GSM_03.40)

  (For PDU Format)

Let's walk through the steps to send an __SMS in PDU Mode__...

TODO

This is how we send an SMS in PDU Mode: [send_sms_pdu](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L255-L341)

Suppose we're sending an SMS to this Phone Number (International Format)...

```text
#define PHONE_NUMBER    "+1234567890"
#define PHONE_NUMBER_PDU "2143658709"
```

Note that we flip the nibbles (half-bytes) from the Original Phone Number to produce the PDU Phone Number.

If the number of nibbles (half-bytes) is odd, insert "F" into the PDU Phone Number like this...

```text
#define PHONE_NUMBER    "+123456789"
#define PHONE_NUMBER_PDU "214365870F9"
```

Assuming there are 10 decimal digits in our Phone Number "+1234567890", here's the AT Command...

```text
// Send SMS Command
const char cmd[] = 
  "AT+CMGS="
  "41"  // TODO: PDU Length in bytes, excluding the Length of SMSC
  "\r";
```

(We'll talk about PDU Length in a while)

And here's the SMS Message PDU that we'll send in the AT Command...

```text
// SMS Message in PDU Format
const char cmd[] = 
  "00"  // Length of SMSC information (None)
  "11"  // SMS-SUBMIT message
  "00"  // TP-Message-Reference: 00 to let the phone set the message reference number itself
  "0A"  // TODO: Address-Length: Length of phone number (Number of Decimal Digits in Phone Number)
  "91"  // Type-of-Address: 91 for International Format of phone number
  PHONE_NUMBER_PDU  // TODO: Phone Number in PDU Format
  "00"  // TP-PID: Protocol identifier
  "08"  // TP-DCS: Data coding scheme
  "01"  // TP-Validity-Period
  "1C"  // TP-User-Data-Length: Length of Encoded Message Text in bytes
  // TP-User-Data: Encoded Message Text "Hello,Quectel!"
  "00480065006C006C006F002C005100750065006300740065006C0021"
  "\x1A";  // End of Message (Ctrl-Z)
```

(We'll talk about Encoded Message Text in a while)

(Remember to update "Address-Length" according to your phone number)

TODO

```c
  // Set Message Format to PDU Mode
  // AT+CMGF=0
  {
    // Write command
    const char cmd[] = "AT+CMGF=0\r";
    write(fd, cmd, strlen(cmd));
    printf("Write command: nbytes=%ld\n%s\n", nbytes, cmd);
    assert(nbytes == strlen(cmd));

    // Read response
    static char buf[1024];
    nbytes = read(fd, buf, sizeof(buf) - 1);
    if (nbytes >= 0) { buf[nbytes] = 0; }
    else { buf[0] = 0; }
    printf("Response: nbytes=%ld\n%s\n", nbytes, buf);

    // Wait a while
    sleep(2);
  }

  // Send SMS Text Message, assuming Message Format is PDU Mode
  // AT+CMGS="yourphonenumber"\r
  // text is entered
  // <Ctrl+Z>
  {
    // Write command
    const char cmd[] = 
      "AT+CMGS="
      "41"  // TODO: PDU Length in bytes, excluding the Length of SMSC
      "\r";
    write(fd, cmd, strlen(cmd));
    printf("Write command: nbytes=%ld\n%s\n", nbytes, cmd);
    assert(nbytes == strlen(cmd));
  }
  // Wait for ">"
  for (;;)
    {
      // Read response
      static char buf[1024];
      ssize_t nbytes = read(fd, buf, sizeof(buf) - 1);
      if (nbytes >= 0) { buf[nbytes] = 0; }
      else { buf[0] = 0; }
      printf("Response: nbytes=%ld\n%s\n", nbytes, buf);

      // Stop if we find ">"
      if (strchr(buf, '>') != NULL) { break; }
    }
  {
    // Write message
    const char cmd[] = 
      "00"  // Length of SMSC information (None)
      "11"  // SMS-SUBMIT message
      "00"  // TP-Message-Reference: 00 to let the phone set the message reference number itself
      "0A"  // TODO: Address-Length: Length of phone number (Number of Decimal Digits in Phone Number)
      "91"  // Type-of-Address: 91 for International Format of phone number
      PHONE_NUMBER_PDU  // TODO: Phone Number in PDU Format
      "00"  // TP-PID: Protocol identifier
      "08"  // TP-DCS: Data coding scheme
      "01"  // TP-Validity-Period
      "1C"  // TP-User-Data-Length: Length of message in bytes
      // TP-User-Data: Encoded Message Text "Hello,Quectel!"
      "00480065006C006C006F002C005100750065006300740065006C0021"
      "\x1A";  // End of Message (Ctrl-Z)
    ssize_t nbytes = write(fd, cmd, strlen(cmd));
    printf("Write command: nbytes=%ld\n%s\n", nbytes, cmd);
    assert(nbytes == strlen(cmd));

    // Read response
    static char buf[1024];
    nbytes = read(fd, buf, sizeof(buf) - 1);
    if (nbytes >= 0) { buf[nbytes] = 0; }
    else { buf[0] = 0; }
    printf("Response: nbytes=%ld\n%s\n", nbytes, buf);

    // Wait a while
    sleep(2);
  }
```

Here's the log...

```text
// Select PDU Mode for SMS (instead of SMS Mode)
Command: AT+CMGF=0
Response: OK

// Send an SMS with 41 bytes (excluding SMSC)
Command: AT+CMGS=41

// Wait for Modem to respond with ">"
Response: > 

// Enter SMS Message in PDU Format, terminate with Ctrl-Z
Command:
0011000A9121436587090008011C00480065006C006C006F002C005100750065006300740065006C0021<Ctrl-Z>

// Modem responds with the Message ID
Response: 
+CMGS: 23
OK
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L663-L681)

- [__"SMS PDU Format"__](https://lupyuen.github.io/articles/lte2#appendix-sms-pdu-format)

- [__"SMS PDU Message Encoding"__](https://lupyuen.github.io/articles/lte2#appendix-sms-pdu-message-encoding)

Let's talk about the SMS PDU...

# SMS Text Mode vs PDU Mode

TODO

_Why send SMS in PDU Mode instead of Text Mode?_

TODO: More reliable (304 Invalid PDU), UTF-16, Receive messages


# AT Modem API

TODO: What about receiving Phone Calls and SMS Messages?

[nRF Connect Modem Library: AT interface](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrfxlib/nrf_modem/doc/at_interface.html)

[uart_lorawan_layer.c](https://github.com/apache/nuttx-apps/blob/master/examples/tcp_ipc_server/uart_lorawan_layer.c#L262-L274)

[esp8266.c](https://github.com/apache/nuttx-apps/blob/master/netutils/esp8266/esp8266.c#L1573-L1582)

# UART vs USB

TODO

# What's Next

TODO

I hope this article was helpful for learning about PinePhone's 4G LTE Modem...

TODO

We'll share more details when the LTE Modem is responding OK to UART and USB on NuttX!

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lte2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lte2.md)

# Appendix: Receive Phone Call and SMS

TODO

```text
RING //A voice call is ringing

AT+CLCC
+CLCC: 1,0,0,1,0,"",128 //PS call in LTE mode
+CLCC: 2,1,4,0,0,"02154450290",129 //Incoming call
OK

ATA //Accept the voice call with ATA
OK
```

[(EG25-G AT Commands, Page 114)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

```text
// Select Message Service 3GPP TS 23.040 and 3GPP TS 23.041
AT+CSMS=1
+CSMS: 1,1,1
OK

// Set SMS Event Reporting Configuration
AT+CNMI=1,2,0,0,0
OK

// Message is dumped directly when an SMS is received
+CMT: "+8615021012496",,"13/03/18,17:07:21+32",145,4,0,0,"+8613800551500",145,28
This is a test from Quectel.

// Send ACK to the network
AT+CNMA
OK
```

[(EG25-G AT Commands, Page 167)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

TODO: Ring Indicator

# Appendix: PCM Digital Audio

TODO

```text
// Get Range of PCM Parameters for Digital Audio
Command: AT+QDAI=?
Response: +QDAI: (1-4),(0,1),(0,1),(0-5),(0-2),(0,1)(1)(1-16)

// Get Current PCM Configuration for Digital Audio
Command: AT+QDAI?
Response: +QDAI: 1,1,0,1,0,0,1,1
```

# Appendix: SMS PDU Format

TODO

_What's the PDU Length?_

Our SMS Message PDU has 42 total bytes...

```text
"00"  // Length of SMSC information (None)
"11"  // SMS-SUBMIT message
"00"  // TP-Message-Reference: 00 to let the phone set the message reference number itself
"0A"  // TODO: Address-Length: Length of phone number (Assume 10  Decimal Digits in Phone Number)
"91"  // Type-of-Address: 91 for International Format of phone number
PHONE_NUMBER_PDU  // TODO: Assume 5 bytes in PDU Phone Number (10 Decimal Digits)
"00"  // TP-PID: Protocol identifier
"08"  // TP-DCS: Data coding scheme
"01"  // TP-Validity-Period
"1C"  // TP-User-Data-Length: Length of Encoded Message Text in bytes
// TP-User-Data: Assume 28 bytes in Encoded Message Text
"00480065006C006C006F002C005100750065006300740065006C0021"
```

PDU Length excludes the SMSC Information (First Byte).

Thus our PDU Length is 41 bytes...

```text
// Send SMS Command
const char cmd[] = 
  "AT+CMGS="
  "41"  // TODO: PDU Length in bytes, excluding the Length of SMSC
  "\r";
```

Remember to update the PDU Length according to your phone number and message text.

_What do the fields mean?_

```text
"00"  // Length of SMSC information (None)
"11"  // SMS-SUBMIT message
"00"  // TP-Message-Reference: 00 to let the phone set the message reference number itself
"0A"  // TODO: Address-Length: Length of phone number (Assume 10 Decimal Digits in Phone Number)
"91"  // Type-of-Address: 91 for International Format of phone number
PHONE_NUMBER_PDU  // TODO: Assume 5 bytes in PDU Phone Number (10 Decimal Digits)
"00"  // TP-PID: Protocol identifier
"08"  // TP-DCS: Data coding scheme
"01"  // TP-Validity-Period
"1C"  // TP-User-Data-Length: Length of Encoded Message Text in bytes
// TP-User-Data: Assume 28 bytes in Encoded Message Text
"00480065006C006C006F002C005100750065006300740065006C0021"
```

- Length of SMSC information: "00"

  We use the default SMS Centre (SMSC), so the SMSC Info Length is 0.

- SM-TL (Short Message Transfer Protocol) TPDU (Transfer Protocol Data Unit) is SMS-SUBMIT Message: "11"

  [(GSM 03.40, TPDU Fields)](https://en.wikipedia.org/wiki/GSM_03.40#TPDU_Fields)

  TP-Message-Type-Indicator (TP-MTI, Bits 0 and 1) is `0b01` (SMS-SUBMIT):

  - Submit a message to SMSC for transmission.

    [(GSM 03.40, TPDU Types)](https://en.wikipedia.org/wiki/GSM_03.40#TPDU_Types)

  TP-Validity-Period-Format (TP-VPF, Bits 3 and 4) is `0b10` (Relative Format):

  - Message Validity Period is in Relative Format.
  
    [(GSM 03.40, Validity Period)](https://en.wikipedia.org/wiki/GSM_03.40#Validity_Period)

    Value of Message Validity Period is in TP-Validity-Period below.
 
- TP-Message-Reference (TP-MR): "00"

  "00" will let the phone generate the Message Reference Number itself

  [(GSM 03.40, Message Reference)](https://en.wikipedia.org/wiki/GSM_03.40#Message_Reference)

- Address-Length: "0A"

  Length of phone number (Number of Decimal Digits in Phone Number, excluding "F")

  [(GSM 03.40, Addresses)](https://en.wikipedia.org/wiki/GSM_03.40#Addresses)

- Type-of-Address: "91"

  91 for International Format of phone number

  Numbering Plan Identification (NPI, Bits 0 to 3) = `0b0001` (ISDN / Telephone Numbering Plan)

  Type Of Number (TON, Bits 4 to 6) = `0b001` (International Number)

  EXT (Bit 7) = `1` (No Extension)

  [(GSM 03.40, Addresses)](https://en.wikipedia.org/wiki/GSM_03.40#Addresses)

- PHONE_NUMBER_PDU: Phone Number in PDU Format (nibbles swapped)

  Remember to insert "F" for odd number of nibbles...

  ```text
  #define PHONE_NUMBER    "+123456789"
  #define PHONE_NUMBER_PDU "214365870F9"
  ```

  [(GSM 03.40, Address Examples)](https://en.wikipedia.org/wiki/GSM_03.40#Address_examples)

- TP-Protocol-Identifier (TP-PID): "00"

  Default Store-and-Forward Short Message

  [(GSM 03.40, Protocol Identifier)](https://en.wikipedia.org/wiki/GSM_03.40#Protocol_Identifier)

- TP-Data-Coding-Scheme (TP-DCS): "08"

  Message Text is encoded with UCS2 Character Set

  [(GSM 03.40, Data Coding Scheme)](https://en.wikipedia.org/wiki/GSM_03.40#Data_Coding_Scheme)

  [(SMS Data Coding Scheme)](https://en.wikipedia.org/wiki/Data_Coding_Scheme#SMS_data_coding_scheme)

- TP-Validity-Period (TP-VP): "01"

  Message is valid for 10 minutes, relative to current time:

  (`"01"` + 1) x 5 minutes

  [(GSM 03.40, Validity Period)](https://en.wikipedia.org/wiki/GSM_03.40#Validity_Period)

  (See TP-Validity-Period-Format above)

- TP-User-Data-Length (TP-UDL): "1C"

  Length of Encoded Message Text in bytes

  [(GSM 03.40, Message Content)](https://en.wikipedia.org/wiki/GSM_03.40#Message_Content)

- TP-User-Data (TP-UD): Encoded Message Text

  Message Text is encoded with UCS2 Character Set

  (Because of TP-Data-Coding-Scheme above)

  [(GSM 03.40, Message Content)](https://en.wikipedia.org/wiki/GSM_03.40#Message_Content)

Let's talk about the Message Text Encoding...

# Appendix: SMS PDU Message Encoding

TODO

_How do we encode the Message Text?_

From the previous section we see that the Message Text is encoded with UCS2 Character Set...

- TP-Data-Coding-Scheme (TP-DCS): "08"

  Message Text is encoded in UCS2 Character Set

  [(GSM 03.40, Data Coding Scheme)](https://en.wikipedia.org/wiki/GSM_03.40#Data_Coding_Scheme)

  [(SMS Data Coding Scheme)](https://en.wikipedia.org/wiki/Data_Coding_Scheme#SMS_data_coding_scheme)

The UCS2 Encoding is actually [Unicode UTF-16](https://en.wikipedia.org/wiki/UTF-16)...

> "the SMS standard specifies UCS-2, but almost all users actually implement UTF-16 so that emojis work"

[(Source)](https://en.wikipedia.org/wiki/UTF-16)

So this Encoded Message Text...

```text
// TP-User-Data: Message Text encoded with UCS2 Character Set
"00480065006C006C006F002C005100750065006300740065006C0021"
```

Comes from the [Unicode UTF-16 Encoding](https://en.wikipedia.org/wiki/UTF-16) of the Message Text "Hello,Quectel!"...

| Character | UTF-16 Encoding |
|:---------:|:---------------:|
| `H` | `0048`
| `e` | `0065`
| `l` | `006C`
| `l` | `006C`
| `o` | `006F`
| `,` | `002C`
| `Q` | `0051`
| `u` | `0075`
| `e` | `0065`
| `c` | `0063`
| `t` | `0074`
| `e` | `0065`
| `l` | `006C`
| `!` | `0021`

(These are 7-Bit ASCII Characters, so the UTF-16 Encoding looks identical to ASCII)
