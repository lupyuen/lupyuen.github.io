# NuttX RTOS for PinePhone: Phone Calls and Text Messages

📝 _4 May 2023_

![Apache NuttX RTOS makes a Phone Call from Pine64 PinePhone](https://lupyuen.github.io/images/lte2-title.jpg)

What makes [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) a phone? Because it will make __Phone Calls__ and send __Text Messages__!

We're porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) to PinePhone. Today let's turn __NuttX into a Feature Phone__...

-   Outgoing and Incoming __Phone Calls__ over 4G

-   Send and receive __SMS Text Messages__

-   Why we prefer __Encoded PDU Messages__ for SMS

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

_How to send AT Commands to LTE Modem?_

The LTE Modem accepts __AT Commands__ in two ways...

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

At __NuttX Startup__, we see this ...

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

On NuttX, this is how we __send an AT Command__ to the LTE Modem over UART3: [hello_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L52-L75)

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

The above NuttX App sends the command "__`AT`__" to the LTE Modem over UART3. (5 times)

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

  LTE Modem is fully operational

  [(EG25-G AT Commands, Page 33)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+CPIN: READY`__"

  4G SIM Card is all ready, no PIN needed

  [(EG25-G AT Commands, Page 60)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+QUSIM: 1`__"

  Identifies the SIM Card Type

  [(Says here)](https://forums.quectel.com/t/what-means-qusim-1/2526/2)

- "__`+QIND: SMS DONE`__"

  SMS Storage is ready

  [(EG25-G AT Commands, Page 297)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+QIND: PB DONE`__"

  Phonebook Storage is ready (for SIM Contacts)

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

In NuttX, this is how we dial a Phone Number to make an __Outgoing Phone Call__: [dial_number](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L343-L432)

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
// ATD+1234567890;
const char cmd[] = 
  "ATD"
  PHONE_NUMBER
  ";\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response
```

[(EG25-G AT Commands, Page 114)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

We __wait 20 seconds__ for the Called Number to answer...

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

    Select __Text Mode__ for SMS
    
    (Instead of PDU Mode)

    [(EG25-G AT Commands, Page 146)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

1.  "__`AT+CSCS="GSM"`__"

    Select (7-bit ASCII-like) __GSM Character Set__
    
    (Instead of 16-bit UCS2 Unicode)

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

    (__Ctrl-Z__ is Character Code __`0x1A`__)

1.  Modem sends our SMS and responds with the __Message ID__...

    ```text
    +CMGS: 22
    ```

    [(EG25-G AT Commands, Page 159)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

This is how we __send an SMS__ (in Text Mode) with NuttX: [send_sms_text](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L162-L253)

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
// AT+CMGS="+1234567890"
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

(My peculiar SIM Card blocks Outgoing SMS, but allows Outgoing Phone Calls)

There's another way to send SMS...

![Send SMS in PDU Mode](https://lupyuen.github.io/images/lte2-pdu.jpg)

# Send SMS in PDU Mode

_Sending an SMS Message looks easy!_

Ah but there's another (preferred and precise) way: __PDU Mode__.

[(__Protocol Data Unit__, works like a Data Packet)](https://en.wikipedia.org/wiki/GSM_03.40)

In PDU Mode, we encode the SMS Messages as __Hexadecimal Numbers__. These are the official docs...

- [__Quectel GSM AT Commands Application Note__](https://www.cika.com/soporte/Information/GSMmodules/Quectel/AppNotes/Quectel_GSM_ATC_Application_Note.pdf)

  (Section 9.3.2 "Send SMS in PDU mode", Page 26)

- [__ETSI GSM 07.05 Spec__](https://www.etsi.org/deliver/etsi_gts/07/0705/05.01.00_60/gsmts_0705v050100p.pdf)

  (For AT Commands)

- [__ETSI GSM 03.40 Spec__](https://en.wikipedia.org/wiki/GSM_03.40)

  (For PDU Format)

Let's walk through the steps to send an __SMS in PDU Mode__...

1.  "__`AT+CMGF=0`__"

    We select PDU Mode for SMS (instead of SMS Mode)

    [(EG25-G AT Commands, Page 146)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

1.  __Phone Numbers__ are a little odd in PDU Mode.

    Suppose we're sending an SMS to this Phone Number (Country Code is mandatory)...

    ```c
    #define PHONE_NUMBER    "+1234567890"
    #define PHONE_NUMBER_PDU "2143658709"
    ```

    Note that we __flip the nibbles__ (half-bytes) from the Original Phone Number to produce the __PDU Phone Number__.

    If the number of __nibbles is odd__, insert "__`F`__" into the PDU Phone Number, like this...

    ```c
    #define PHONE_NUMBER    "+123456789"
    #define PHONE_NUMBER_PDU "214365870F9"
    ```

1.  Let's assume there are 10 Decimal Digits in the destination Phone Number: "__`+1234567890`__" (Country Code is mandatory)

    This is the AT Command to __send an SMS__...

    ```c
    // Send an SMS with 41 bytes (excluding SMSC)
    const char cmd[] = 
      "AT+CMGS="
      "41"  // TODO: PDU Length in bytes, excluding the Length of SMSC
      "\r";
    ```

    (More about PDU Length in a while)

    [(EG25-G AT Commands, Page 159)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

1.  __Wait for Modem__ to respond with "__`>`__"

1.  __Enter SMS Message__ in PDU Format, like this...

    ```c
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

    (More about these fields in a while)

    (Remember to set "__Address-Length__" according to the destination Phone Number)

1.  Modem sends our SMS and responds with the __Message ID__...

    ```text
    +CMGS: 23
    ```

    [(EG25-G AT Commands, Page 159)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

Let's look at the NuttX Code: [send_sms_pdu](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L255-L341)

```c
// Select PDU Mode for SMS (instead of SMS Mode)
const char cmd[] = "AT+CMGF=0\r";
write(fd, cmd, strlen(cmd));
// Omitted: Read response and wait 2 seconds

// Send an SMS with 41 bytes (excluding SMSC)
const char cmd[] = 
  "AT+CMGS="
  "41"  // TODO: PDU Length in bytes, excluding the Length of SMSC
  "\r";
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

// Enter SMS Message in PDU Format, terminate with Ctrl-Z
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
write(fd, cmd, strlen(cmd));

// Omitted: Read response and wait 2 seconds
// Modem responds with the Message ID
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

And our SMS Message __"Hello,Quectel!"__ appears at the destination Phone Number!

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L663-L681)

_How to encode the SMS in PDU Format? What's the PDU Length?_

The __PDU Encoding for SMS__ is explained here...

- [__"SMS PDU Format"__](https://lupyuen.github.io/articles/lte2#appendix-sms-pdu-format)

- [__"SMS PDU Message Encoding"__](https://lupyuen.github.io/articles/lte2#appendix-sms-pdu-message-encoding)

_What if we get Error 304?_

```text
+CMS ERROR: 304
```

The LTE Modem tells us that the __PDU Encoding is invalid__.

Check the docs above to verify the PDU Encoding for our SMS Message.

Let's find out why we prefer PDU Mode over Text Mode...

[(__For Error 305:__ Check the SMSC and SIM)](https://lupyuen.github.io/articles/lte2#send-sms-in-text-mode)

# SMS Text Mode vs PDU Mode

_Why send SMS in PDU Mode instead of Text Mode?_

Sending SMS Messages in Text Mode looks easier. But we __should use PDU Mode__ instead. Here's why...

__Text Mode:__ This is how we send an SMS...

```text
// Text Mode: How many characters in this SMS?
AT+CMGS="+1234567890"

// Followed by Message Text...
```

__PDU Mode:__ This is how we do it...

```text
// PDU Mode: 41 bytes in this SMS (excluding SMSC)
AT+CMGS=41

// Followed by SMS Message encoded as PDU...
```

See the difference? __PDU Mode is more precise__ because we state exactly how many bytes there are in the SMS.

With Text Mode, there's a risk of garbled messages when characters are dropped during UART Transmission.

(Which happens!)

_But what if characters are dropped in PDU Mode?_

The LTE Modem will say it's an __Invalid PDU__...

```text
+CMS ERROR: 304
```

Our app should catch this error and resend.

# AT Modem API

_What about receiving Phone Calls and SMS Messages?_

We handle __Incoming Phone Calls and SMS__ like this...

- [__"Receive Phone Call and SMS"__](https://lupyuen.github.io/articles/lte2#appendix-receive-phone-call-and-sms)

And it looks messy. LTE Modem will __dump a Notification__ whenever there's an Incoming Call or SMS...

```text
// Incoming Call Notification
RING
// We answer the call with ATA
...
// Incoming SMS Notification
+CMT: "+8615021012496",,"13/03/18,17:07:21+32",145,4,0,0,"+8613800551500",145,28
// Followed by Message Text
```

Which is totally __Asynchronous__. And tricky to handle over UART.

_Any other UART problems with LTE Modem?_

Our [__UART Output__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L562-L621) looks all jumbled up because our NuttX App didn't __wait for the response__ of every AT Command...

| NuttX App writes | LTE Modem responds |
|:-----------------|:-------------------|
| `AT`
|    | `RDY`
| `AT`
|    | `+CFUN: 1`
| `AT`
|    | `AT` <br> `OK` <br> `+CPIN: READY` <br> `+QUSIM: 1` <br> `+QIND: SMS DONE`
| __`AT+CREG?`__ <br> _(Where's the CREG response?)_
|    | `AT` <br> `OK`
| `AT+COPS?`
|    | __`AT+CREG?`__ <br> `+CREG: 0,1` <br> `OK` <br> _(Oops CREG response is delayed!)_

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L562-L621)

Our NuttX App should have waited for the response of "__`AT+CREG`__"... Before sending "__`AT+COPS`__"!

_So we wait for OK or ERROR. Piece of cake right?_

But hold up! Remember that __UART might drop characters__...

- What if the LTE Modem __never received__ our AT Command?

- What if the __OK__ or __ERROR__ response is missing or corrupted?

Our NuttX App needs a __robust parser__ for responses.

And our app needs to __timeout gracefully__ if we don't get a timely response. (Then retry)

_Is there a proper Modem API for AT Commands?_

__nRF Connect Modem Library__ has a nifty AT Interface. We might adapt it for NuttX...

- [__nRF Connect Modem Library: AT Interface__](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrfxlib/nrf_modem/doc/at_interface.html)

The AT Modem API uses __printf__ and __scanf__ to handle AT Commands...

```c
// Send command "AT+CFUN"
err = modem_at_printf("AT+CFUN=%d", mode);

// Check commnd result
if (err = 0) {
  // "OK" success
} else if (err > 0) {
  // Response is not "OK"
  switch(modem_at_err_type(err)) {
    // Modem returned "ERROR"
    case NRF_MODEM_AT_ERROR: ...
```

[(Source)](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrfxlib/nrf_modem/doc/at_interface.html)

And it handles __AT Notifications as Callbacks__. [(Like this)](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrfxlib/nrf_modem/doc/at_interface.html#receiving-at-notifications)

(Very nice!)

_Anything we might reuse from NuttX?_

The NuttX Sample Apps for __LoRaWAN and ESP8266__ will do some (very limited) AT Command Handling. We might copy bits of these...

- [__uart_lorawan_layer.c__](https://github.com/apache/nuttx-apps/blob/master/examples/tcp_ipc_server/uart_lorawan_layer.c#L262-L274)

- [__esp8266.c__](https://github.com/apache/nuttx-apps/blob/master/netutils/esp8266/esp8266.c#L1573-L1582)

_Wow this looks tedious. If only we had reliable, non-lossy UART..._

We do! The LTE Modem supports reliable communication over [__USB Serial__](https://lupyuen.github.io/articles/usb3).

Which we'll explore later when our USB Serial Driver is up!

[(__UART Hardware Flow Control__ won't work on PinePhone)](https://lupyuen.github.io/articles/lte#main-uart-interface)

But first we need to __upstream these to NuttX Mainline__...

- [__Allwinner A64 UART Driver__](https://github.com/lupyuen/pinephone-nuttx#configure-uart-port) (for UART3)

- [__Quectel EG25-G LTE Modem Driver__](https://lupyuen.github.io/articles/lte#power-up-wth-nuttx) (for PinePhone)

# What's Next

I hope this article was helpful for understanding the internals of Phone Calls and Text Messaging on PinePhone...

-   Outgoing and Incoming __Phone Calls__ over 4G

-   Send and receive __SMS Text Messages__

-   Why we prefer __Encoded PDU Messages__ for SMS

-   Programming the __4G LTE Modem__ with Apache NuttX RTOS

-   Doing all these over __UART vs USB__

-   Upcoming __AT Modem API__ for robust parsing, graceful timeout (plus retry) and notification callbacks

We'll share more details when the AT Modem API is up on NuttX!

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss on Reddit__](https://www.reddit.com/r/PINE64official/comments/136ao1g/nuttx_rtos_for_pinephone_phone_calls_and_text/)

-   [__Discuss on Hacker News__](https://news.ycombinator.com/item?id=35798118)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lte2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lte2.md)

![Ring Indicator is connected to GPIO Pin PL6](https://lupyuen.github.io/images/lte-title3.jpg)

[_Ring Indicator is connected to GPIO Pin PL6_](https://lupyuen.github.io/articles/lte#control-pins-for-lte-modem)

# Appendix: Receive Phone Call and SMS

_How do we receive Phone Calls and SMS Messages with the LTE Modem?_

We receive an __Incoming Phone Call__ like this...

```text
// Notification for Incoming Voice Call
RING

// List the Current Calls
AT+CLCC

// Outgoing Call: Call Type is Packet Switched Call (LTE Mode)
+CLCC: 1,0,0,1,0,"",128

// Incoming Call: Voice, Non-Multiparty, Phone Number, Unknown Number Type
+CLCC: 2,1,4,0,0,"02154450290",129
OK

// Accept the Voice Call
ATA
OK
```

[(EG25-G AT Commands, Page 114)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

And we __receive an SMS__ (in Text Mode) like this...

```text
// Select Message Service 3GPP TS 23.040 and 3GPP TS 23.041
AT+CSMS=1
+CSMS: 1,1,1
OK

// Set SMS Event Reporting Configuration
AT+CNMI=1,2,0,0,0
OK

// Notification for Incoming SMS
+CMT: "+8615021012496",,"13/03/18,17:07:21+32",145,4,0,0,"+8613800551500",145,28
This is a test from Quectel.

// Send ACK to the network
AT+CNMA
OK
```

[(EG25-G AT Commands, Page 167)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

Receiving an SMS in __PDU Mode__ will look slightly different.

_How does the Ring Indicator work with Incoming Call and SMS?_

The LTE Modem sets [__Ring Indicator (GPIO Pin PL6)__](https://lupyuen.github.io/articles/lte#control-pins-for-lte-modem) to High when there's an Incoming Call or SMS. (Pic above)

Which we configure like this...

```text
// For Incoming Calls: Signal the Ring Indicator
AT+QCFG="urc/ri/ring"

// For Incoming SMS: Signal the Ring Indicator
AT+QCFG="urc/ri/smsincoming" 
```

[(EG25-G AT Commands, Page 46)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

![LTE Modem is connected to Port PCM0 for Digital Audio](https://lupyuen.github.io/images/lte-title4.jpg)

[_LTE Modem is connected to Port PCM0 for Digital Audio_](https://lupyuen.github.io/articles/lte#control-pins-for-lte-modem)

# Appendix: PCM Digital Audio

_Earlier we made an Outgoing Voice Call..._

_How will we talk to the called Phone Number?_

LTE Modem is connected to Allwinner A64 __Port PCM0__ for the __PCM Digital Audio__ Input and Output. (Pic above)

We send the "__`AT+QDAI`__" commands for the __PCM Digital Audio__ setup. We're still working on it...

```text
// Get Range of PCM Parameters for Digital Audio
Command: AT+QDAI=?
Response: +QDAI: (1-4),(0,1),(0,1),(0-5),(0-2),(0,1)(1)(1-16)

// Get Current PCM Configuration for Digital Audio
Command: AT+QDAI?
Response: +QDAI: 1,1,0,1,0,0,1,1
```

[(EG25-G AT Commands, Page 233)](https://wiki.pine64.org/images/1/1b/Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

The above __PCM Digital Audio Configuration__ for the LTE Modem says...

- __io = 1__

  Digital PCM Output 

- __mode = 1__

  Slave Mode

- __fsync = 0__

  Primary Mode (short-synchronization)

- __clock = 1__

  Clock Frequency is 256 kHz

- __format = 0__

  Data Format is 16-bit linear

- __sample = 0__

  Sampling Rate is 8 kHz

- __num_slots = 1__

  Number of Slot is 1

- __slot_mapping = 1__

  Slot Mapping Value is 1

This (excellent) article explains how we'll program Port PCM0 to transmit and receive the Digital Audio Stream...

- [__"Genode: PinePhone Telephony"__](https://genodians.org/ssumpf/2022-05-09-telephony)

# Appendix: SMS PDU Format

_Earlier we saw this command for sending SMS in PDU Mode..._

_What's the PDU Length?_

```text
// Send an SMS with PDU Length of 41 bytes (excluding SMSC)
Command: AT+CMGS=41
```

Our SMS Message PDU has __42 total bytes__...

```c
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

But PDU Length __excludes the SMS Centre Information__. (First Byte)

Thus our PDU Length is __41 bytes__...

```c
// Send SMS Command
const char cmd[] = 
  "AT+CMGS="
  "41"  // TODO: PDU Length in bytes, excluding the Length of SMSC
  "\r";
```

Remember to __update the PDU Length__ according to your phone number and message text.

_What do the PDU Fields mean?_

```c
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

- __Length of SMSC information:__ "`00`"

  We use the default SMS Centre (SMSC), so the SMSC Info Length is 0.

  ("__`AT+CSCA?`__" shows the SMSC)

- __Short Message Transfer Protocol__ (SM-TL) __Transfer Protocol Data Unit__ (TPDU) is SMS-SUBMIT Message: "`11`"

  [(GSM 03.40, TPDU Fields)](https://en.wikipedia.org/wiki/GSM_03.40#TPDU_Fields)

  __TP-Message-Type-Indicator__ (TP-MTI, Bits 0 and 1) = `0b01` (SMS-SUBMIT):

  - Submit a message to SMSC for transmission.

    [(GSM 03.40, TPDU Types)](https://en.wikipedia.org/wiki/GSM_03.40#TPDU_Types)

  __TP-Validity-Period-Format__ (TP-VPF, Bits 3 and 4) = `0b10` (Relative Format):

  - __Message Validity Period__ is in Relative Format.
  
    [(GSM 03.40, Validity Period)](https://en.wikipedia.org/wiki/GSM_03.40#Validity_Period)

    (Value of Message Validity Period is in __TP-Validity-Period__ below)
 
- __TP-Message-Reference__ (TP-MR): "`00`"

  "`00`" will let the phone generate the Message Reference Number itself

  [(GSM 03.40, Message Reference)](https://en.wikipedia.org/wiki/GSM_03.40#Message_Reference)

- __Address-Length:__ "`0A`"

  Length of phone number
  
  (Number of Decimal Digits in Phone Number, excluding "`F`")

  [(GSM 03.40, Addresses)](https://en.wikipedia.org/wiki/GSM_03.40#Addresses)

- __Type-of-Address:__ "`91`"

  "`91`" for International Format of Phone Number

  __Numbering Plan Identification__ (NPI, Bits 0 to 3) = `0b0001` (ISDN / Telephone Numbering Plan)

  __Type Of Number__ (TON, Bits 4 to 6) = `0b001` (International Number)

  __EXT__ (Bit 7) = `1` (No Extension)

  [(GSM 03.40, Addresses)](https://en.wikipedia.org/wiki/GSM_03.40#Addresses)

- __PHONE_NUMBER_PDU:__ Phone Number in PDU Format (nibbles swapped)

  ```c
  #define PHONE_NUMBER    "+1234567890"
  #define PHONE_NUMBER_PDU "2143658709"
  ```

  Remember to insert "`F`" if Phone Number has __odd number of nibbles__...

  ```c
  #define PHONE_NUMBER    "+123456789"
  #define PHONE_NUMBER_PDU "214365870F9"
  ```

  [(GSM 03.40, Address Examples)](https://en.wikipedia.org/wiki/GSM_03.40#Address_examples)

- __TP-Protocol-Identifier__ (TP-PID): "`00`"

  Default Store-and-Forward Short Message

  [(GSM 03.40, Protocol Identifier)](https://en.wikipedia.org/wiki/GSM_03.40#Protocol_Identifier)

- __TP-Data-Coding-Scheme__ (TP-DCS): "`08`"

  Message Text is encoded with __UCS2 Unicode Character Set__

  [(GSM 03.40, Data Coding Scheme)](https://en.wikipedia.org/wiki/GSM_03.40#Data_Coding_Scheme)

  [(SMS Data Coding Scheme)](https://en.wikipedia.org/wiki/Data_Coding_Scheme#SMS_data_coding_scheme)

- __TP-Validity-Period__ (TP-VP): "`01`"

  Message is valid for 10 minutes, relative to current time:

  `("01" + 1) x 5` minutes

  [(GSM 03.40, Validity Period)](https://en.wikipedia.org/wiki/GSM_03.40#Validity_Period)

  (See __TP-Validity-Period-Format__ above)

- __TP-User-Data-Length__ (TP-UDL): "`1C`"

  Length of Encoded Message Text (in bytes)

  [(GSM 03.40, Message Content)](https://en.wikipedia.org/wiki/GSM_03.40#Message_Content)

- __TP-User-Data__ (TP-UD): Encoded Message Text

  Message Text is encoded with __UCS2 Unicode Character Set__

  (Because of __TP-Data-Coding-Scheme__ above)

  [(GSM 03.40, Message Content)](https://en.wikipedia.org/wiki/GSM_03.40#Message_Content)

Let's talk about the Message Text Encoding...

# Appendix: SMS PDU Message Encoding

_How do we encode the Message Text in PDU Mode?_

From the previous section we see that the Message Text is encoded with __UCS2 Character Set__...

- __TP-Data-Coding-Scheme__ (TP-DCS): "`08`"

  Message Text is encoded in __UCS2 Unicode Character Set__

  [(GSM 03.40, Data Coding Scheme)](https://en.wikipedia.org/wiki/GSM_03.40#Data_Coding_Scheme)

  [(SMS Data Coding Scheme)](https://en.wikipedia.org/wiki/Data_Coding_Scheme#SMS_data_coding_scheme)

The UCS2 Encoding is actually [__Unicode UTF-16__](https://en.wikipedia.org/wiki/UTF-16)...

"the SMS standard specifies UCS-2, but almost all users actually __implement UTF-16__ so that emojis work"

[(Source)](https://en.wikipedia.org/wiki/UTF-16)

So this Encoded Message Text...

```c
// TP-User-Data: Message Text encoded with UCS2 Character Set
"00480065006C006C006F002C005100750065006300740065006C0021"
```

Comes from the [__Unicode UTF-16 Encoding__](https://en.wikipedia.org/wiki/UTF-16) of the Message Text "`Hello,Quectel!`"...

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
