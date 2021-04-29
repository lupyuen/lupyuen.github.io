# Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway

📝 _3 May 2021_

While testing a new LoRaWAN gadget ([PineCone BL602](https://lupyuen.github.io/articles/lora2)), I bought a LoRaWAN Gateway from RAKwireless: [__RAK7248 WisGate Developer D4H Gateway__](https://docs.rakwireless.com/Product-Categories/WisGate/RAK7248/Datasheet/).

Here's what I learnt about __settting up a LoRaWAN Network__ with WisGate Developer D4H... And testing it with the __RAKwireless WisBlock dev kit in Arduino__.

![RAKwireless RAK7248 WisGate Developer D4H LoRaWAN Gateway](https://lupyuen.github.io/images/wisgate-title.jpg)

_RAKwireless RAK7248 WisGate Developer D4H LoRaWAN Gateway_

# WisGate D4H Hardware

WisGate D4H is essentially a Raspberry Pi 4 + LoRa Network Concentrator in a sturdy IP30 box.

It exposes the same ports and connectors as a Raspberry Pi 4: Ethernet port, USB 2 and 3 ports, USB-C power, microSD Card.

But the HDMI and GPIO ports are no longer accessible. (We control the box over HTTP and SSH)

![RAKwireless RAK7248 WisGate Developer D4H LoRaWAN Gateway](https://lupyuen.github.io/images/wisgate-hw.jpg)

2 new connectors have been added...

1.  __LoRa Antenna__ (left)

1.  __GPS Antenna__ (right)

(The two connectors are slightly different, so we won't connect the wrong antenna)

The GPS Antenna will be used when we connect WisGate to The Things Network (the worldwide free-access LoRaWAN network).

WisGate D4H is shipped with the open-source ChirpStack LoRaWAN stack, preinstalled in the microSD card. 

(Yep please don't peel off the sticky tape and insert your own microSD card)

![microSD Slot on WisGate D4H](https://lupyuen.github.io/images/wisgate-hw2.jpg)

_microSD Slot on WisGate D4H_

# ChirpStack LoRaWAN Stack

Connect the LoRa Antenna to GPS Antenna to WisGate before powering on. (To prevent damage to the RF modules)

Follow the instructions here to start the WisGate box and to connect to the preinstalled ChirpStack LoRaWAN stack...

-   [__"RAK7244C Quick Start Guide"__](https://docs.rakwireless.com/Product-Categories/WisGate/RAK7244C/Quickstart/)

(RAK7244C is quite similar to our RAK7248 gateway)

I connected an Ethernet cable to WisGate and used SSH to configure the WiFi and LAN settings (via `sudo gateway-config`).

Here's the ChirpStack web admin page that we will see...

![ChirpStack web admin on WisGate](https://lupyuen.github.io/images/wisgate-chirpstack.png)

(Nope I'm nowhere near Jervois Road)

In the left bar, click __`Gateways`__ to see our pre-configured LoRaWAN Gateway...

![ChirpStack web admin on WisGate](https://lupyuen.github.io/images/wisgate-chirpstack2.png)

Click __`rak-gateway`__ to see the Gateway Details...

![ChirpStack web admin on WisGate](https://lupyuen.github.io/images/wisgate-chirpstack3.png)

This shows that my WisGate gateway receives __1,200 LoRaWAN Packets a day__ from unknown LoRaWAN Devices nearby.

WisGate won't do anything with the received LoRaWAN Packets since it's not configured to process packets with mysterious origins.

(But we may click __`Live LoRaWAN Frames`__ at top right to see the encrypted contents of the received LoRaWAN Packets)

# LoRaWAN Application

TODO

Click __`Applications`__ then __`app`__...

![ChirpStack Application](https://lupyuen.github.io/images/wisgate-app.png)

Take note of the second __Device EUI__...

![ChirpStack Application](https://lupyuen.github.io/images/wisgate-app2.png)

(EUI sounds like we stepped on something unpleasant... But it actually means [__Extended Unique Identifier__](https://lora-developers.semtech.com/library/tech-papers-and-guides/the-book/deveui/
))

We shall set this Device EUI in our Arduino program in a while...

```c
uint8_t nodeDeviceEUI[8] = { 0x4b, 0xc1, 0x5e, 0xe7, 0x37, 0x7b, 0xb1, 0x5b };
```

Click __`device_ptaa_class_a`__ because we'll be doing __Over-The-Air Activation (OTAA)__ for our Arduino device

![ChirpStack Application](https://lupyuen.github.io/images/wisgate-app3.png)

Click __`Keys (OTAA)`__

Under `Application Key`, click the circular arrow to generate a random key.

Take note of the generated __Application Key__, we shall set this in our Arduino program...

```c
uint8_t nodeAppKey[16] = { 0xaa, 0xff, 0xad, 0x5c, 0x7e, 0x87, 0xf6, 0x4d, 0xe3, 0xf0, 0x87, 0x32, 0xfc, 0x1d, 0xd2, 0x5d };
```

Click __`Set Device-Keys`__

# LoRaWAN Arduino Client

TODO

![RAKwireless RAK4630 WisBlock LPWAN Module mounted on WisBlock Base Board](https://lupyuen.github.io/images/wisblock-title.jpg)

_RAKwireless RAK4630 WisBlock LPWAN Module mounted on WisBlock Base Board_

Source code...

[`github.com/lupyuen/wisblock-lorawan`](https://github.com/lupyuen/wisblock-lorawan)

Arduino LoRaWAN client for [RAKwireless WisBlock RAK4630](https://docs.rakwireless.com/Product-Categories/WisBlock/Quickstart/).

See...

[LoRaWAN Examples for WisBlock RAK4630](https://github.com/RAKWireless/WisBlock/tree/master/examples/RAK4630/communications/LoRa/LoRaWAN)

Based on...

[`LoRaWAN_OTAA_ABP.ino`](https://github.com/RAKWireless/WisBlock/blob/master/examples/RAK4630/communications/LoRa/LoRaWAN/LoRaWAN_OTAA_ABP/LoRaWAN_OTAA_ABP.ino)

Note: This program needs SX126x-Arduino Library version 2.0.0 or later. 

In [`platformio.ini`](https://github.com/lupyuen/wisblock-lorawan/blob/master/platformio.ini) set...

```text
lib_deps = beegee-tokyo/SX126x-Arduino@^2.0.0
```

# Initialise LoRaWAN Client in Arduino

TODO

[__Watch the video on YouTube__](https://youtu.be/xdyi6XCo8Z8)

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L38-L58)

```c
//  TODO: Set this to your LoRaWAN Region
LoRaMacRegion_t g_CurrentRegion = LORAMAC_REGION_AS923;
```

TODO

```c
//  Set to true to select Over-The-Air Activation 
//  (OTAA), false for Activation By Personalisation (ABP)
bool doOTAA = true;
```

TODO

```c
//  TODO: (For OTAA Only) Set the OTAA keys. KEYS ARE MSB !!!!

//  Device EUI: Copy from ChirpStack: 
//  Applications -> app -> Device EUI
uint8_t nodeDeviceEUI[8] = { 0x4b, 0xc1, 0x5e, 0xe7, 0x37, 0x7b, 0xb1, 0x5b };

//  App EUI: Not needed for ChirpStack, 
//  set to default 0000000000000000
uint8_t nodeAppEUI[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

//  App Key: Copy from ChirpStack: 
//  Applications -> app -> Devices -> 
//  device_otaa_class_a -> Keys (OTAA) -> 
//  Application Key
uint8_t nodeAppKey[16] = { 0xaa, 0xff, 0xad, 0x5c, 0x7e, 0x87, 0xf6, 0x4d, 0xe3, 0xf0, 0x87, 0x32, 0xfc, 0x1d, 0xd2, 0x5d };
```

TODO

```c
//  TODO: (For ABP Only) Set the ABP keys
uint32_t nodeDevAddr = 0x260116F8;
uint8_t nodeNwsKey[16] = { 0x7E, 0xAC, 0xE2, 0x55, 0xB8, 0xA5, 0xE2, 0x69, 0x91, 0x51, 0x96, 0x06, 0x47, 0x56, 0x9D, 0x23 };
uint8_t nodeAppsKey[16] = { 0xFB, 0xAC, 0xB6, 0x47, 0xF3, 0x58, 0x45, 0xC7, 0x50, 0x7D, 0xBF, 0x16, 0x8B, 0xA8, 0xC1, 0x7C };
```

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L110-L213)

```c
// At startup, we join the LoRaWAN network, in either OTAA or ABP mode
void setup() {
  ...
  // Initialize LoRa chip.
  lora_rak4630_init();

  // Omitted: Initialize Serial for debug output
  ...
  
  // Create a timer to send data to server periodically
  uint32_t err_code err_code = timers_init();
  if (err_code != 0) { return; }
```

TODO

```c
  // Setup the EUIs and Keys
  if (doOTAA) {
    // Set the keys for OTAA
    lmh_setDevEui(nodeDeviceEUI);
    lmh_setAppEui(nodeAppEUI);
    lmh_setAppKey(nodeAppKey);
  } else {
    // Omitted: Set the keys for ABP
    ...
  }
```

TODO

```c
  // Initialize LoRaWaN
  err_code = lmh_init(  //  lmh_init now takes 3 parameters instead of 5
    &g_lora_callbacks,  //  Callbacks 
    g_lora_param_init,  //  Functions
    doOTAA,             //  Set to true for OTAA
    g_CurrentClass,     //  Class 
    g_CurrentRegion     //  Region
  );
  if (err_code != 0) { return; }
```

TODO

```
  // Start Join procedure
  lmh_join();
}
```

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L87-L97)

```c
//  Structure containing LoRaWan callback functions, 
//  needed for lmh_init()
static lmh_callback_t g_lora_callbacks = {
    BoardGetBatteryLevel, 
    BoardGetUniqueId, 
    BoardGetRandomSeed,
    lorawan_rx_handler, 
    lorawan_has_joined_handler, 
    lorawan_confirm_class_handler, 
    lorawan_join_failed_handler
};
```

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L215-L220)

```c
//  Nothing here for now
void loop() {
  //  Put your application tasks here, like reading of sensors,
  //  Controlling actuators and/or other functions. 
}
```

# Join LoRaWAN Network in Arduino

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L222-L236)

```c
//  LoRa function for handling HasJoined event
void lorawan_has_joined_handler(void) {
  //  When we have joined the LoRaWAN network, 
  //  start a 20-second timer
  lmh_error_status ret = lmh_class_request(g_CurrentClass);
  if (ret == LMH_SUCCESS) {
    delay(1000);
    TimerSetValue(&appTimer, LORAWAN_APP_INTERVAL);
    TimerStart(&appTimer);
  }
}
```

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L238-L246)

```c
//  LoRa function for handling OTAA join failed
static void lorawan_join_failed_handler(void) {
  //  If we can't join the LoRaWAN network, show the error
  Serial.println("OTAA join failed!");
}
```

In case you're curious: WisBlock transmits this LoRaWAN Packet to WisGate when requesting to join the LoRaWAN network...

![Join LoRaWAN Network Request](https://lupyuen.github.io/images/wisgate-join.png)

# Send LoRaWAN Packets in Arduino

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L269-L300)

```c
//  This is called when the 20-second timer expires. 
//  We send a LoRaWAN Packet.
void send_lora_frame(void) {
  if (lmh_join_status_get() != LMH_SET) {
    //  Not joined, try again later
    return;
  }

  uint32_t i = 0;
  memset(m_lora_app_data.buffer, 0, LORAWAN_APP_DATA_BUFF_SIZE);
  m_lora_app_data.port = gAppPort;
  m_lora_app_data.buffer[i++] = 'H';
  m_lora_app_data.buffer[i++] = 'e';
  m_lora_app_data.buffer[i++] = 'l';
  m_lora_app_data.buffer[i++] = 'l';
  m_lora_app_data.buffer[i++] = 'o';
  m_lora_app_data.buffer[i++] = '!';
  m_lora_app_data.buffsize = i;

  lmh_error_status error = lmh_send(
    &m_lora_app_data, 
    g_CurrentConfirm
  );
  if (error == LMH_SUCCESS) { count++; } 
  else { count_fail++; }
}
```

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L302-L311)

```c
//  Function for handling timerout event
void tx_lora_periodic_handler(void) {
  //  When the 20-second timer has expired, 
  //  send a LoRaWAN Packet and restart the timer
  TimerSetValue(&appTimer, LORAWAN_APP_INTERVAL);
  TimerStart(&appTimer);
  send_lora_frame();
}
```

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L313-L321)

```c
//  Initialise the timer
uint32_t timers_init(void) {
  TimerInit(&appTimer, tx_lora_periodic_handler);
  return 0;
}
```

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L259-L267)

```c
//  Callback Function that is called when we have joined the LoRaWAN network with a LoRaWAN Class
void lorawan_confirm_class_handler(DeviceClass_t Class) {
  //  Informs the server that switch has occurred ASAP
  m_lora_app_data.buffsize = 0;
  m_lora_app_data.port = gAppPort;
  lmh_send(&m_lora_app_data, g_CurrentConfirm);
}
```

TODO

[`From main.cpp`](https://github.com/lupyuen/wisblock-lorawan/blob/master/src/main.cpp#L248-L257)

```c
//  Function for handling LoRaWan received data from Gateway
void lorawan_rx_handler(lmh_app_data_t *app_data) {
  //  When we receive a LoRaWAN Packet from the 
  //  LoRaWAN Gateway, display it
  Serial.printf("LoRa Packet received on port %d, size:%d, rssi:%d, snr:%d, data:%s\n",
    app_data->port, app_data->buffsize, app_data->rssi, app_data->snr, app_data->buffer);
}
```

# Output Log

TODO

From [`wisblock-lorawan`](https://github.com/lupyuen/wisblock-lorawan/blob/master/README.md#output-log)

```text
<LMH> OTAA 
DevEui=4B-C1-5E-E7-37-7B-B1-5B
DevAdd=00000000
AppEui=00-00-00-00-00-00-00-00
AppKey=AA-FF-AD-5C-7E-87-F6-4D-E3-F0-87-32-FC-1D-D2-5D
SX126xSetTxParams: power=0, rampTime=4
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1 
SX126xSetTxParams: power=13, rampTime=2
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1 
<LMH> Selected subband 1
Joining LoRaWAN network...
SX126xSetTxParams: power=13, rampTime=2
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1 
RadioSend: size=23, channel=1, datarate=2, txpower=0, maxeirp=16, antennagain=2
00 00 00 00 00 00 00 00 00 5b b1 7b 37 e7 5e c1 4b 0d 42 dd b9 22 aa 
<LM> OnRadioTxDone
<LM> OnRadioTxDone => RX Windows #1 5002 #2 6002
<LM> OnRadioTxDone => TX was Join Request
<LM> OnRadioRxDone
<LM> OnRadioRxDone => FRAME_TYPE_JOIN_ACCEPT
OTAA Mode, Network Joined!
```

TODO

```text
Sending frame now...
SX126xSetTxParams: power=13, rampTime=2
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1 
RadioSend: size=19, channel=0, datarate=2, txpower=0, maxeirp=16, antennagain=2
40 3c 59 7a 00 80 00 00 02 17 77 31 fd 99 86 8f 4f cc ef 
lmh_send ok count 1
<LM> OnRadioTxDone
<LM> OnRadioTxDone => RX Windows #1 1002 #2 2002
<RADIO> RadioIrqProcess => IRQ_RX_TX_TIMEOUT
<LM> OnRadioRxTimeout
```

TODO

```
Sending frame now...
SX126xSetTxParams: power=13, rampTime=2
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1 
RadioSend: size=19, channel=5, datarate=2, txpower=0, maxeirp=16, antennagain=2
40 3c 59 7a 00 80 01 00 02 0b 1f 7e 4d e1 94 c9 16 fa ea 
lmh_send ok count 2
<LM> OnRadioTxDone
<LM> OnRadioTxDone => RX Windows #1 1002 #2 2002
<RADIO> RadioIrqProcess => IRQ_RX_TX_TIMEOUT
<LM> OnRadioRxTimeout
```

# View Received LoRaWAN Packets

TODO

# Troubleshoot LoRaWAN

TODO

# Visualise LoRaWAN with Software Defined Radio

TODO

[__Watch the video on YouTube__](https://youtu.be/xdyi6XCo8Z8)

# LoRaWAN Join Request

TODO

# LoRaWAN Message Integrity Code

TODO

To search for Message Integrity Code errors in LoRaWAN Packets received by WisGate, SSH to WisGate and search for...

```bash
# grep MIC /var/log/syslog

Apr 28 04:02:05 rak-gateway 
chirpstack-application-server[568]: 
time="2021-04-28T04:02:05+01:00" 
level=error 
msg="invalid MIC" 
dev_eui=4bc15ee7377bb15b 
type=DATA_UP_MIC

Apr 28 04:02:05 rak-gateway 
chirpstack-network-server[1378]: 
time="2021-04-28T04:02:05+01:00" 
level=error 
msg="uplink: processing uplink frame error"
ctx_id=0ccd1478-3b79-4ded-9e26-a28e4c143edc 
error="get device-session error: invalid MIC"
```

# LoRaWAN Nonce

TODO

The error above occurs when we replay a repeated Join Network Request to our LoRaWAN Gateway (with same Nonce, same Message Integrity Code).

This replay also logs a Nonce Error in WisGate...

```bash
# grep nonce /var/log/syslog

Apr 28 04:02:41 rak-gateway chirpstack-application-server[568]:
time="2021-04-28T04:02:41+01:00" 
level=error 
msg="validate dev-nonce error" 
dev_eui=4bc15ee7377bb15b 
type=OTAA

Apr 28 04:02:41 rak-gateway chirpstack-network-server[1378]:
time="2021-04-28T04:02:41+01:00" 
level=error 
msg="uplink: processing uplink frame error" ctx_id=01ae296e-8ce1-449a-83cc-fb0771059d89 
error="validate dev-nonce error: object already exists"
```

Because the Nonce should not be reused.

["LoRaWAN® Is Secure (but Implementation Matters)"](https://lora-alliance.org/resource_hub/lorawan-is-secure-but-implementation-matters/)

# Log Transmitted Packets

To log transmitted packets, modify

`.pio/libdeps/wiscore_rak4631/SX126x-Arduino/src/mac/LoRaMac.cpp`

```c
LoRaMacStatus_t SendFrameOnChannel(uint8_t channel)
{
    TxConfigParams_t txConfig;
    int8_t txPower = 0;

    txConfig.Channel = channel;
    txConfig.Datarate = LoRaMacParams.ChannelsDatarate;
    txConfig.TxPower = LoRaMacParams.ChannelsTxPower;
    txConfig.MaxEirp = LoRaMacParams.MaxEirp;
    txConfig.AntennaGain = LoRaMacParams.AntennaGain;
    txConfig.PktLen = LoRaMacBufferPktLen;

    // If we are connecting to a single channel gateway we use always the same predefined channel and datarate
    if (singleChannelGateway)
    {
        txConfig.Channel = singleChannelSelected;
        txConfig.Datarate = singleChannelDatarate;
    }

    RegionTxConfig(LoRaMacRegion, &txConfig, &txPower, &TxTimeOnAir);

    MlmeConfirm.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
    McpsConfirm.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
    McpsConfirm.Datarate = LoRaMacParams.ChannelsDatarate;
    McpsConfirm.TxPower = txPower;

    // Store the time on air
    McpsConfirm.TxTimeOnAir = TxTimeOnAir;
    MlmeConfirm.TxTimeOnAir = TxTimeOnAir;

    // Starts the MAC layer status check timer
    TimerSetValue(&MacStateCheckTimer, MAC_STATE_CHECK_TIMEOUT);
    TimerStart(&MacStateCheckTimer);

    if (IsLoRaMacNetworkJoined != JOIN_OK)
    {
        JoinRequestTrials++;
    }

    //////////////// INSERT THIS CODE

    // To replay a Join Network Request...
    // if (LoRaMacBuffer[0] == 0) {
    // 	static uint8_t replay[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xb1, 0x7b, 0x37, 0xe7, 0x5e, 0xc1, 0x4b, 0x67, 0xaa, 0xbb, 0x07, 0x70, 0x7d};
    // 	memcpy(LoRaMacBuffer, replay, LoRaMacBufferPktLen);
    // }

    // To dump transmitted packets...
    printf("RadioSend: size=%d, channel=%d, datarate=%d, txpower=%d, maxeirp=%d, antennagain=%d\r\n", (int) LoRaMacBufferPktLen, (int) txConfig.Channel, (int) txConfig.Datarate, (int) txConfig.TxPower, (int) txConfig.MaxEirp, (int) txConfig.AntennaGain);
    for (int i = 0; i < LoRaMacBufferPktLen; i++) {
        printf("%02x ", LoRaMacBuffer[i]);
    }
    printf("\r\n");
    
    //////////////// END OF INSERTION

    // Send now
    Radio.Send(LoRaMacBuffer, LoRaMacBufferPktLen);

    LoRaMacState |= LORAMAC_TX_RUNNING;

    return LORAMAC_STATUS_OK;
}
```

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/wisgate.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/wisgate.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1379926160377851910)

