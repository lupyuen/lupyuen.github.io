# NuttX RTOS for PinePhone: Phone Calls and Text Messages

📝 _1 May 2023_

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

-   [__EG25-G AT Commands__](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

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

![LTE Modem Power](https://lupyuen.github.io/images/lte-power2.png)

[_Power Key and Reset are __High-Low Inverted__ for PinePhone_](https://lupyuen.github.io/articles/lte#power-on-lte-modem)

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

But it hangs there. No response!

The LTE Modem might take [__30 seconds__](https://lupyuen.github.io/articles/lte#is-lte-modem-up) to become operational. Be patient, the response appears in a while...

```text
Response:
RDY
```

"__`RDY`__" means that the LTE Modem is ready for AT Commands!

[(EG25-G AT Commands, Page 297)](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

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

  [(EG25-G AT Commands, Page 33)](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+CPIN: READY`__"

  4G SIM Card is all ready, no PIN needed

  [(EG25-G AT Commands, Page 60)](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+QUSIM: 1`__"

  Identifies SIM card type

  [(Says here)](https://forums.quectel.com/t/what-means-qusim-1/2526/2)

- "__`+QIND: SMS DONE`__"

  SMS is ready

  [(EG25-G AT Commands, Page 297)](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

- "__`+QIND: PB DONE`__"

  Phonebook is ready (for SIM Contacts)

  [(EG25-G AT Commands, Page 297)](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

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

Right now let's make some phone calls!

![NuttX makes a Phone Call from PinePhone](https://lupyuen.github.io/images/lte2-title.jpg)

[_NuttX makes a Phone Call from PinePhone_](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L683-L735)

# Outgoing Phone Call

TODO

This is the NuttX App that makes a Phone Call on PinePhone: [dial_number](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L343-L432)

Here's the output...

```text
NuttShell (NSH) NuttX-12.0.3
nsh> hello

// Check Modem Status
Command: AT
Response:
RDY
+CFUN: 1
+CPIN: READY
+QUSIM: 1
+QIND: SMS DONE
// SIM and SMS are ready

// Check Network Status
Command: AT+CREG?
Response:
+CREG: 0,1
+QIND: PB DONE
// Network and Phonebook are ready

// Get Network Operator
Command: AT+COPS?
Response: +COPS: 0,0,"SGP-M1",7

// Get Range of PCM Parameters for Digital Audio
Command: AT+QDAI=?
Response: +QDAI: (1-4),(0,1),(0,1),(0-5),(0-2),(0,1)(1)(1-16)

// Get Current PCM Configuration for Digital Audio
Command: AT+QDAI?
Response: +QDAI: 1,1,0,1,0,0,1,1

// Make Outgoing Phone Call
Command: ATDyourphonenumber;
Response:
OK

// Receiver has hung up
Response:
NO CARRIER

// Hang up Phone Call
Command: ATH
Response: OK
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L562-L737)

TODO: What does this say: `+QDAI: 1,1,0,1,0,0,1,1`

![NuttX sends an SMS in Text Mode](https://lupyuen.github.io/images/lte2-sms.jpg)

[_NuttX sends an SMS in Text Mode_](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L622-L659)

# Send SMS in Text Mode

TODO

This is how we send an SMS in Text Mode: [send_sms_text](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L162-L253)

Here's the log...

```text
// Set Message Format to Text Mode
Command: AT+CMGF=1
Response: OK

// Set Character Set to GSM
Command: AT+CSCS="GSM"
Response: OK

// Send an SMS to the Phone Number.
// yourphonenumber looks like +1234567890
// Works without country code, like 234567890
Command:
AT+CMGS="yourphonenumber"

// We wait for Modem to respond with ">"
Response:
> 

// SMS Message in Text Format, terminate with Ctrl-Z
Command:
Hello from Apache NuttX RTOS on PinePhone! (SMS Text Mode)<Ctrl-Z>

// Modem sends the SMS Message
Response:
+CMGS: 13
OK
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L622-L659)

_Why do we get Error 350 sometimes? (Rejected by SMSC)_

```text
+CMS ERROR: 350
```

Maybe the Modem isn't ready to transmit SMS? Should we retry?

# Send SMS in PDU Mode

TODO

Now we send an SMS Message in PDU Mode. Based on...

- [Quectel GSM AT Commands Application Note](https://www.cika.com/soporte/Information/GSMmodules/Quectel/AppNotes/Quectel_GSM_ATC_Application_Note.pdf), Section 9.3.2 "Send SMS in PDU mode", Page 26

- [ETSI GSM 07.05 Spec](https://www.etsi.org/deliver/etsi_gts/07/0705/05.01.00_60/gsmts_0705v050100p.pdf) (AT Commands)

- [ETSI GSM 03.40 Spec](https://en.wikipedia.org/wiki/GSM_03.40) (PDU Format)

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

Here's the log...

```text
// Set Message Format to PDU Mode
Command: AT+CMGF=0
Response: OK

// Send an SMS with 41 bytes (excluding SMSC)
Command: AT+CMGS=41

// We wait for Modem to respond with ">"
Response: > 

// SMS Message in PDU Format, terminate with Ctrl-Z.
// yourphonenumberpdu looks like 2143658709, which represents +1234567890
// Country Code is mandatory. Remember to insert "F" for odd number of nibbles.
Command:
0011000A91yourphonenumberpdu0008011C00480065006C006C006F002C005100750065006300740065006C0021<Ctrl-Z>

// Modem sends the SMS Message
Response: 
+CMGS: 14
OK
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/8ea4208cbd4758a0f1443c61bffa7ec4a8390695/examples/hello/hello_main.c#L663-L681)

Let's talk about the SMS PDU...

# SMS PDU Format

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

_How do we encode the Message Text?_

From above we see that the Message Text is encoded with UCS2 Character Set...

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

# SMS Text Mode vs PDU Mode

TODO

_Why send SMS in PDU Mode instead of Text Mode?_

TODO: More reliable (304 Invalid PDU), UTF-16, Receive messages

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

[(EG25-G AT Commands, Page 167)](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

# Receive Phone Call

TODO

# Receive SMS

TODO

# AT Modem API

TODO

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
