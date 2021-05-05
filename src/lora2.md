# PineCone BL602 RISC-V Board Receives LoRa Packets

📝 _4 Apr 2021_

Not too long ago (and not so far away) we embarked on an epic quest to create a low-power, long-range [__LoRa IoT Sensor__](https://en.wikipedia.org/wiki/LoRa) with [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone)

1.  We created a __LoRa Transmitter__ with BL602...

    [__"Connect PineCone BL602 to LoRa Transceiver"__](https://lupyuen.github.io/articles/lora)

1.  Then we tested it with a __LoRa Receiver__: RAKwireless WisBlock...

    [__"RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/wisblock)

Today we shall create the LoRa Firmware for BL602 that will __Receive LoRa Packets__. And test it with RAKwireless WisBlock as the LoRa Transmitter.

_Why do we need to receive LoRa Packets... If our BL602 LoRa Sensor will only transmit sensor data?_

Because we'll soon connect our BL602 LoRa Sensor to a __secure, managed LoRaWAN Network__ like [__The Things Network__](https://www.thethingsnetwork.org/). (Or maybe [__Helium__](https://www.helium.com/lorawan))

Our BL602 gadget can't join these networks unless it can receive packets and respond to the network.

Let's make it so! (Because we do... Or do not... There is no try!)

The LoRa Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

-   [__Watch the demo video on YouTube__](https://youtu.be/3TSvo0dwwnQ)

-   [__More about the 3 Levels of LoRa and LoRaWAN__](https://lupyuen.github.io/articles/lora#lora-vs-lorawan)

[__UPDATE: We have a new LoRa Driver for SX1262 (Pine64 RFM90 LoRa Module)... Check this out__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/3rdparty/lora-sx1262)

![PineCone BL602 RISC-V Board with Hope RF96 LoRa Transceiver (top) receives LoRa packets from RAKwireless WisBlock (bottom)](https://lupyuen.github.io/images/lora2-title.jpg)

_PineCone BL602 RISC-V Board with Hope RF96 LoRa Transceiver (top) receives LoRa packets from RAKwireless WisBlock (bottom)_

# Connect BL602 to LoRa Transceiver

Connect BL602 to Semtech SX1276 or Hope RF96 as follows...

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora2-connect3.jpg)

| BL602 Pin     | SX1276 / RF96 Pin   | Wire Colour 
|:--------------|:--------------------|:-------------------
| __`GPIO 0`__  | `DIO1`              | Dark Green
| __`GPIO 1`__  | `ISO` _(MISO)_      | Light Green (Top)
| __`GPIO 2`__  | Do Not Connect      | (Unused Chip Select)
| __`GPIO 3`__  | `SCK`               | Yellow (Top)
| __`GPIO 4`__  | `OSI` _(MOSI)_      | Blue (Top)
| __`GPIO 5`__  | `DIO2`              | Blue (Bottom)
| __`GPIO 11`__ | `DIO0`              | Yellow (Bottom)
| __`GPIO 12`__ | `DIO3`              | Light Green (Bottom)
| __`GPIO 14`__ | `NSS`               | Orange
| __`GPIO 17`__ | `RST`               | White
| __`3V3`__     | `3.3V`              | Red
| __`GND`__     | `GND`               | Black

[__CAUTION: Always connect the Antenna before Powering On... Or the LoRa Transceiver may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

Here's a closer look at the pins connected on BL602...

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora2-connect4.jpg)

_Why is BL602 Pin 2 unused?_

__`GPIO 2`__ is the __Unused SPI Chip Select__ on BL602.

We won't use this pin because we'll control Chip Select ourselves on `GPIO 14`. [(See this)](https://lupyuen.github.io/articles/spi#control-our-own-chip-select-pin)

Here are the pins connected on our LoRa Transceiver: SX1276 or RF96...

(`ISO` and `OSI` appear flipped in this pic... Rotate your phone / computer screen 180 degrees for the proper perspective)

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora2-connect5.jpg)

_Why do we connect so many pins on SX1276 (or RF96)?_

The SX1276 and RF96 transceivers have __6 (!) Digital Input / Output pins: `DIO0` to `DIO5`__

The transceiver shifts the Logic Levels of these pins from __Low to High__ when specific conditions occur...

-   __`DIO0` Packet Received__: This pin is triggered when the transceiver __receives a LoRa Packet.__

    `DIO0` is also triggered after the transceiver has transmitted a LoRa Packet, but that's not so useful.

-   __`DIO1` Receive Timeout__: This pin is triggered when the transceiver __doesn't receive any LoRa Packets__ within a timeout window.

    This works only when the transceiver is configured for __Single Receive Mode__.

    However today we're configuring our transceiver for __Continuous Receive Mode__ so we won't be using `DIO1`. We shall trigger receive timeouts with a BL602 Timer.

-   __`DIO2` Change Channel__: This is used for __Spread Spectrum Transmission__ (Frequency Hopping). 

    When we transmit / receive LoRa Packets over multiple frequencies (spread spectrum), we reduce the likelihood of packet collisions over the airwaves.

    We won't be using Spread Spectrum Transmission today, so `DIO2` shall stay idle.

-   __`DIO3` Channel Activity Detection__: The transceiver lets us __detect whether there's any ongoing transmission__ in a LoRa Radio Channel, in a power-efficient way.

    We won't be using Channel Activity Detection today.

-   __`DIO4`__ and __`DIO5`__ are not connected to BL602.  They are used for __FSK Radio Modulation__ only.

    (We're using LoRa Radio Modulation)

Only __1 pin `DIO0`__ is required for receiving simple LoRa Packets, without the frills (like Spread Spectrum Transmission).

But for now we shall connect __4 pins `DIO0` to `DIO3`__, just in case they will be needed later for LoRaWAN. (Which will probably use Spread Spectrum Transmission)

We shall configure BL602 to trigger __GPIO Interrupts__ when the 4 pins shift from Low to High.

-   [__More about Semtech SX1276 and Hope RF96__](https://lupyuen.github.io/articles/lora#getting-the-lora-transceiver-and-antenna)

-   [__Semtech SX1276 Datasheet__](https://semtech.my.salesforce.com/sfc/p/E0000000JelG/a/2R0000001Rbr/6EfVZUorrpoKFfvaF_Fkpgp5kzjiNyiAbqcpqh9qSjE?__hstc=212684107.81023fceb80b3e55c1c4e19a916804ba.1616925682449.1616925682449.1616925682449.1&__hssc=212684107.1.1616925682449&__hsfp=1469659345)

# Initialise LoRa Transceiver

Let's look at the code inside our LoRa Firmware for BL602: `sdk_app_lora`

__Super Important:__ We should set the LoRa Frequency in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L43-L58) like so...

```c
/// TODO: We are using LoRa Frequency 923 MHz 
/// for Singapore. Change this for your region.
#define USE_BAND_923
```

In a while we shall change `923` to the LoRa Frequency for our region: `434`, `780`, `868`, `915` or `923` MHz. [(Check this list)](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

For now we'll study this function __`init_driver`__ that initialises the LoRa Driver for SX1276 (and RF96) in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L126-L179)

```c
/// Command to initialise the SX1276 / RF96 driver
static void init_driver(char *buf, int len, int argc, char **argv) {
    //  Set the LoRa Callback Functions
    RadioEvents_t radio_events;
    memset(&radio_events, 0, sizeof(radio_events));  //  Must init radio_events to null, because radio_events lives on stack!
    radio_events.TxDone    = on_tx_done;
    radio_events.RxDone    = on_rx_done;
    radio_events.TxTimeout = on_tx_timeout;
    radio_events.RxTimeout = on_rx_timeout;
    radio_events.RxError   = on_rx_error;
```

`init_driver` begins by defining the __Callback Functions__ that will be called when we have transmitted or received a LoRa Packet (successfully or unsuccessfully)...

-   __Packet Transmitted: `on_tx_done`__

    Called when the transceiver has successfully transmitted a LoRa Packet.

-   __Packet Received: `on_rx_done`__

    Called when the tranceiver has received a LoRa Packet. (More about this in a while)

-   __Transmit Timeout: `on_tx_timeout`__

    Called if the transceiver is unable to transmit a LoRa Packet.

-   __Receive Timeout: `on_rx_timeout`__:

    Called if the transceiver doesn't receive any LoRa Packets within a timeout window. (More about this in a while)

-   __Receive Error: `on_rx_error`__:

    Called if the transceiver encounters an error when receiving a LoRa Packet. (More about this in a while)

Next we call __`Radio.Init` to initialise BL602's SPI Port and the LoRa Transceiver__...

```c
    //  Init the SPI Port and the LoRa Transceiver
    Radio.Init(&radio_events);
```

`Radio.Init` will set some registers on our LoRa Transceiver (over SPI).

Then we call __`Radio.SetChannel` to set the LoRa Frequency__...

```c
    //  Set the LoRa Frequency, which is specific to our region.
    //  For USE_BAND_923: RF_FREQUENCY is set to 923000000.
    Radio.SetChannel(RF_FREQUENCY);
```

`Radio.SetChannel` configures the LoRa Frequency by writing to the __Frequency Registers__ in our LoRa Transceiver.

We get ready to transmit by calling __`Radio.SetTxConfig`__...

```c
    //  Configure the LoRa Transceiver for transmitting messages
    Radio.SetTxConfig(
        MODEM_LORA,
        LORAPING_TX_OUTPUT_POWER,
        0,        //  Frequency deviation: Unused with LoRa
        LORAPING_BANDWIDTH,
        LORAPING_SPREADING_FACTOR,
        LORAPING_CODINGRATE,
        LORAPING_PREAMBLE_LENGTH,
        LORAPING_FIX_LENGTH_PAYLOAD_ON,
        true,     //  CRC enabled
        0,        //  Frequency hopping disabled
        0,        //  Hop period: N/A
        LORAPING_IQ_INVERSION_ON,
        LORAPING_TX_TIMEOUT_MS
    );
```

At the end of the function we call __`Radio.SetRxConfig`__ to configure the transceiver for receiving LoRa Packets...

```c
    //  Configure the LoRa Transceiver for receiving messages
    Radio.SetRxConfig(
        MODEM_LORA,
        LORAPING_BANDWIDTH,
        LORAPING_SPREADING_FACTOR,
        LORAPING_CODINGRATE,
        0,        //  AFC bandwidth: Unused with LoRa
        LORAPING_PREAMBLE_LENGTH,
        LORAPING_SYMBOL_TIMEOUT,
        LORAPING_FIX_LENGTH_PAYLOAD_ON,
        0,        //  Fixed payload length: N/A
        true,     //  CRC enabled
        0,        //  Frequency hopping disabled
        0,        //  Hop period: N/A
        LORAPING_IQ_INVERSION_ON,
        true      //  Continuous receive mode
    );    
}
```

_What's Continuous Receive Mode?_

__Continuous Receive Mode__ means that the transceiver will wait forever for incoming packets... Until we tell it to stop.

(We'll stop the transceiver with a BL602 Timer)

But before that, we need to tell the transceiver to begin receiving packets. That's coming up next...

(The code in this article is based on the [LoRa Ping](https://github.com/apache/mynewt-core/blob/master/apps/loraping/src/main.c) program from Mynewt OS. [More about this](https://lupyuen.github.io/articles/lora#appendix-porting-lora-driver-from-mynewt-to-bl602))

# Receive LoRa Packet

We're creating a __battery-powered__ IoT Sensor with LoRa.

To conserve battery power, we don't listen for incoming LoRa Packets all the time... We __listen for 5 seconds__ then go to sleep.

This is how we do it: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L207-L213)

```c
/// LoRa Receive Timeout in 5 seconds
#define LORAPING_RX_TIMEOUT_MS 5000  //  Milliseconds

/// Command to receive a LoRa message. Assume that SX1276 / RF96 driver has been initialised.
/// Assume that create_task has been called to init the Event Queue.
static void receive_message(char *buf, int len, int argc, char **argv) {
    //  Receive a LoRa message within 5 seconds
    Radio.Rx(LORAPING_RX_TIMEOUT_MS);
}
```

The __`receive_message`__ command calls __`Radio.Rx`__ (from the SX1276 Driver) to receive a LoRa Packet within 5 seconds.

## Receive Callback

Upon receiving the LoRa Packet, the SX1276 Driver calls the Callback Function __`on_rx_done`__ in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L355-L381)

```c
/// Callback Function that is called when a LoRa message has been received
static void on_rx_done(
    uint8_t *payload,  //  Buffer containing received LoRa message
    uint16_t size,     //  Size of the LoRa message
    int16_t rssi,      //  Signal strength
    int8_t snr) {      //  Signal To Noise ratio

    //  Switch the LoRa Transceiver to low power, sleep mode
    Radio.Sleep();
```

At the start of `on_rx_done`, we __power down the LoRa Transceiver__ to conserve battery power.

Next we __copy the received packet__ into our 64-byte buffer __`loraping_buffer`__...

```c
    //  Copy the received packet (up to 64 bytes)
    if (size > sizeof loraping_buffer) {
        size = sizeof loraping_buffer;
    }
    loraping_rx_size = size;
    memcpy(loraping_buffer, payload, size);
```

At the end of the callback, we __display the contents__ of the copied packet...

```c
    //  Dump the contents of the received packet
    for (int i = 0; i < loraping_rx_size; i++) {
        printf("%02x ", loraping_buffer[i]);
    }
    printf("\r\n");

    //  Log the signal strength, signal to noise ratio
    loraping_rxinfo_rxed(rssi, snr);
}
```

_Is it really OK to call `printf` here?_

Yes because this code runs in the context of the __FreeRTOS Application Task__, not in the context of the Interrupt Handler. We'll learn why in a while.

(This differs from the original [LoRa Ping](https://github.com/apache/mynewt-core/blob/master/apps/loraping/src/main.c) program... On Mynewt OS, `on_rx_done` and other Callback Functions will run in the context of the Interrupt Handler)

## Timeout and Error Callbacks

_What happens when we don't receive a LoRa Packet in 5 seconds?_

The SX1276 Driver calls our Callback Function __`on_rx_timeout`__ that's defined in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L398-L412)

```c
/// Callback Function that is called when no LoRa messages could be received due to timeout
static void on_rx_timeout(void) {
    //  Switch the LoRa Transceiver to low power, sleep mode
    Radio.Sleep();

    //  Log the timeout
    loraping_stats.rx_timeout++;
    loraping_rxinfo_timeout();
}
```

Here we power down the LoRa Transceiver to conserve battery power.

We do the same in the Callback Function __`on_rx_error`__, which the SX1276 Driver calls when it hits an error receiving LoRa Packets: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L414-L427)

```c
/// Callback Function that is called when we couldn't receive a LoRa message due to error
static void on_rx_error(void) {
    //  Log the error
    loraping_stats.rx_error++;

    //  Switch the LoRa Transceiver to low power, sleep mode
    Radio.Sleep();
}
```

# BL602 GPIO Interrupts

Let's talk about __handling GPIO Interrupts__ on BL602...

![BL602 handling GPIO interrupts](https://lupyuen.github.io/images/lora2-interrupt.png)

1.  When our LoRa Transceiver (SX1276) __receives a LoRa Packet__...

1.  It shifts the Logic Level of __Pin `DIO0` from Low to High__

1.  We shall configure BL602 to detect this shift in the connected GPIO Pin and trigger a __GPIO Interrupt__

1.  The __GPIO Interrupt Handler__ in our firmware code will then process the received LoRa Packet. (And reset `DIO0` back to Low)

Here's how we configure a GPIO Interrupt Handler on BL602: [`sx1276-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L144-L240)

```c
//  SX1276 DIO0 is connected to BL602 at GPIO 11
#define SX1276_DIO0 11

//  Register GPIO Handler for DIO0
int rc = register_gpio_handler(   //  Register GPIO Handler...
    SX1276_DIO0,                  //  GPIO Pin Number
    SX1276OnDio0Irq,              //  GPIO Handler Function
    GLB_GPIO_INT_CONTROL_ASYNC,   //  Async Control Mode
    GLB_GPIO_INT_TRIG_POS_PULSE,  //  Trigger when GPIO level shifts from Low to High
    0,                            //  No pullup
    0                             //  No pulldown
);
assert(rc == 0);
```

This call to __`register_gpio_handler`__ says...

1.  When BL602 detects __GPIO Pin 11__ (connected to `DIO0`) shifting from __Low to High__ (Positive Edge)...

1.  BL602 will call our GPIO Handler Function __`SX1276OnDio0Irq`__

We'll cover `register_gpio_handler` in the next section.

Then to enable GPIO Interrupts we call these functions from the __BL602 Interrupt Hardware Abstraction Layer (HAL)__...

```c
//  Register Common Interrupt Handler for GPIO Interrupt
bl_irq_register_with_ctx(
    GPIO_INT0_IRQn,         //  GPIO Interrupt
    handle_gpio_interrupt,  //  Interrupt Handler
    NULL                    //  Argument for Interrupt Handler
);

//  Enable GPIO Interrupt
bl_irq_enable(GPIO_INT0_IRQn);
```

__`handle_gpio_interrupt`__ is the low-level __Interrupt Handler__ that will be called by the BL602 GPIO HAL when the GPIO Interrupt is triggered.

We'll look inside `handle_gpio_interrupt` in a while.

## Register Handler Function

Let's look inside our function __`register_gpio_handler`__ and learn how it __registers a Handler Function for GPIO__: [`sx1276-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L341-L403)

```c
/// Register Handler Function for GPIO. Return 0 if successful.
/// GPIO Handler Function will run in the context of the Application Task, not the Interrupt Handler.
/// Based on bl_gpio_register in https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.c
static int register_gpio_handler(
    uint8_t gpioPin,         //  GPIO Pin Number
    DioIrqHandler *handler,  //  GPIO Handler Function
    uint8_t intCtrlMod,      //  GPIO Interrupt Control Mode (see below)
    uint8_t intTrgMod,       //  GPIO Interrupt Trigger Mode (see below)
    uint8_t pullup,          //  1 for pullup, 0 for no pullup
    uint8_t pulldown) {      //  1 for pulldown, 0 for no pulldown
```

Above are the parameters for `register_gpio_handler`.

The __GPIO Interrupt Control Modes__ are...

-   __`GLB_GPIO_INT_CONTROL_SYNC`__:  Synchronous Mode

    (We never use sync mode)

-   __`GLB_GPIO_INT_CONTROL_ASYNC`__: Asynchronous Mode

    (We ALWAYS use async mode)

The BL602 Reference Manual doesn't mention GPIO Interrupt Control modes. But according to the BL602 HAL code, only __Async Mode__ should be used. [(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_button.c#L309)

The __GPIO Interrupt Trigger Mode__ specifies how the GPIO should trigger the interrupt...

-   __`GLB_GPIO_INT_TRIG_NEG_PULSE`__: Negative Edge Pulse Trigger

    Trigger the interrupt when the GPIO Logic Level shifts from __High to Low__

-   __`GLB_GPIO_INT_TRIG_POS_PULSE`__: Positive Edge Pulse Trigger

    Trigger the interrupt when the GPIO Logic Level shifts from __Low to High__

    (We use this for SX1276)

-   __`GLB_GPIO_INT_TRIG_NEG_LEVEL`__: Negative Edge Level Trigger (32k 3T)

    Trigger the interrupt when the GPIO Logic Level stays __Low__

-   __`GLB_GPIO_INT_TRIG_POS_LEVEL`__: Positive Edge Level Trigger (32k 3T)

    Trigger the interrupt when the GPIO Logic Level stays __High__

The GPIO Interrupt Trigger Mode is (partially) documented in the [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) (Section 3.2.12: "GPIO Interrupt"). [(This BL602 HAL code offers more hints)](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_button.c#L270-L312)

Our GPIO Handler Function `handler` shall be triggered through an Event (from the NimBLE Porting Layer). We'll learn why later...

```c
    //  Init the Event that will invoke the handler for the GPIO Interrupt
    int rc = init_interrupt_event(
        gpioPin,  //  GPIO Pin Number
        handler   //  GPIO Handler Function that will be triggered by the Event
    );
    assert(rc == 0);
```

Next we call `GLB_GPIO_Func_Init` to configure the pin as a __GPIO Pin__...

```c
    //  Configure pin as a GPIO Pin
    GLB_GPIO_Type pins[1];
    pins[0] = gpioPin;
    BL_Err_Type rc2 = GLB_GPIO_Func_Init(
        GPIO_FUN_SWGPIO,  //  Configure as GPIO 
        pins,             //  Pins to be configured
        sizeof(pins) / sizeof(pins[0])  //  Number of pins (1)
    );
    assert(rc2 == SUCCESS);    
```

`GLB_GPIO_Func_Init` comes from the BL602 Standard Driver: [`bl602_glb.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c)

We configure the pin as a __GPIO Input Pin__ (instead of GPIO Output)...

```c
    //  Configure pin as a GPIO Input Pin
    rc = bl_gpio_enable_input(
        gpioPin,  //  GPIO Pin Number
        pullup,   //  1 for pullup, 0 for no pullup
        pulldown  //  1 for pulldown, 0 for no pulldown
    );
    assert(rc == 0);
```

Finally we disable the GPIO Pin Interrupt, configure the __GPIO Interrupt Control and Trigger Modes__, and enable the GPIO Pin Interrupt...

```c
    //  Disable GPIO Interrupt for the pin
    bl_gpio_intmask(gpioPin, 1);

    //  Configure GPIO Pin for GPIO Interrupt
    bl_set_gpio_intmod(
        gpioPin,     //  GPIO Pin Number
        intCtrlMod,  //  GPIO Interrupt Control Mode (see below)
        intTrgMod    //  GPIO Interrupt Trigger Mode (see below)
    );

    //  Enable GPIO Interrupt for the pin
    bl_gpio_intmask(gpioPin, 0);
    return 0;
}
```

We're ready to handle GPIO Interrupts triggered by our LoRa Transceiver!

_There seems to be 2 types of GPIO Interrupts?_

Yep, earlier we saw this...

```c
//  Enable GPIO Interrupt
bl_irq_enable(GPIO_INT0_IRQn);
```

This enables the GPIO Interrupt for __ALL GPIO Pins__ (by calling the BL602 Interrupt HAL).

Then we saw this...

```c
//  Enable GPIO Interrupt for the pin
bl_gpio_intmask(gpioPin, 0);
```

This enables the GPIO Interrupt for __ONE Specific GPIO Pin__ (by calling the BL602 GPIO HAL).

We need both to make GPIO Interrupts work.

## GPIO Interrupt Handler

_GPIO Interrupt Handler vs GPIO Handler Function... Are these different things?_

I'm sorry to muddle my dearest readers, they are indeed different things and they work at different levels...

![GPIO Interrupt Handler vs GPIO Handler Function](https://lupyuen.github.io/images/lora2-handler.png)

1.  __GPIO Interrupt Handler__ (`handle_gpio_interrupt`) is the low-level __Interrupt Service Routine__ that handles the GPIO Interrupt.

    This Interrupt Handler (called by BL602 Interrupt HAL) services the GPIO Interrupt that's triggered when SX1276 receives a LoRa Packet.

1.  __GPIO Handler Function__ (like `SX1276OnDio0Irq`) is the high-level __Application Function__ (running in a FreeRTOS Task) that processes the received LoRa Packet.

    This Handler Function is invoked (indirectly) by the Interrupt Handler (via an Event from NimBLE Porting Layer).

    (What's an Event and why are we using it? We'll learn about the NimBLE Porting Layer in the next chapter)

Let's study the low-level __GPIO Interrupt Handler `handle_gpio_interrupt`__ that services all GPIO Interrupts: [`sx1276-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L405-L433)

```c
/// Maximum number of GPIO Pins that can be configured for interrupts
#define MAX_GPIO_INTERRUPTS 6  //  DIO0 to DIO5

/// Array of GPIO Pin Numbers that have been configured for interrupts
static uint8_t gpio_interrupts[MAX_GPIO_INTERRUPTS];

/// Array of Events for the GPIO Interrupts
static struct ble_npl_event gpio_events[MAX_GPIO_INTERRUPTS];

/// Interrupt Handler for GPIO Pins DIO0 to DIO5
static void handle_gpio_interrupt(void *arg) {

    //  Check all GPIO Interrupt Events
    for (int i = 0; i < MAX_GPIO_INTERRUPTS; i++) {

        //  Get the GPIO Pin Number for the Event
        GLB_GPIO_Type gpioPin = gpio_interrupts[i];

        //  Get the GPIO Interrupt Event
        struct ble_npl_event *ev = &gpio_events[i];
```

We start the GPIO Interrupt Handler `handle_gpio_interrupt` by __iterating through the GPIO Interrupts__ that we have configured (for `DIO0` to `DIO5`).

The configured GPIO Interrupts are stored in arrays __`gpio_interrupts` and `gpio_events`__ like so...

![GPIO Interrupts and Events](https://lupyuen.github.io/images/lora2-events.png)

For the first iteration...

-   Since `DIO0` is connected to __GPIO Pin 11__...

    __`gpioPin`__ shall be set to __`11`__

    (Via `gpio_interrupts[0]`)

-   Since `DIO0` is handled by the __GPIO Handler Function `SX1276OnDio0Irq`__...

    __`ev`__ shall be set to the Event that points to __`SX1276OnDio0Irq`__

    (Via `gpio_events[0]`)

    (More about `gpio_interrupts` and `gpio_events` in the next chapter)

We allow unused GPIO Pins, and we skip them like so...

```c
        //  If the Event is unused, skip it
        if (ev->fn == NULL) { continue; }
```

Next we fetch the __Interrupt Status__ of the GPIO Pin, to determine whether this GPIO Pin has triggered the interrupt...

```c
        //  Get the Interrupt Status of the GPIO Pin
        BL_Sts_Type status = GLB_Get_GPIO_IntStatus(gpioPin);
```

`GLB_Get_GPIO_IntStatus` comes from the BL602 Standard Driver: [`bl602_glb.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c)

If this GPIO Pin has indeed triggered the interrupt, we __enqueue the Event__ (containing our GPIO Handler Function) for the Application Task to handle...

```c
        //  If the GPIO Pin has triggered an interrupt...
        if (status == SET) {
            //  Forward the GPIO Interrupt to the Application Task to process
            enqueue_interrupt_event(
                gpioPin,  //  GPIO Pin Number
                ev        //  Event that will be enqueued for the Application Task
            );
        }
    }
}
```

In summary: Our GPIO Interrupt Handler...

1.  Iterates through all configured GPIO Interrupts (`DIO0` to `DIO5`)

1.  Hunts for the GPIO Interrupts that have been triggered

1.  Enqueues the GPIO Event (and Handler Function) for processing by the Application Task

Let's look at `enqueue_interrupt_event`...

## Enqueue Interrupt Event

The time has come to reveal the final piece of code that handles GPIO Interrupts: __`enqueue_interrupt_event`__ from [`sx1276-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L435-L469)

```c
/// Interrupt Counters
int g_dio0_counter, g_dio1_counter, g_dio2_counter, g_dio3_counter, g_dio4_counter, g_dio5_counter, g_nodio_counter;

/// Enqueue the GPIO Interrupt to an Event Queue for the Application Task to process
static int enqueue_interrupt_event(
    uint8_t gpioPin,                //  GPIO Pin Number
    struct ble_npl_event *event) {  //  Event that will be enqueued for the Application Task

    //  Disable GPIO Interrupt for the pin
    bl_gpio_intmask(gpioPin, 1);
```

We start by disabling the GPIO Interrupt for the pin.

Here's a helpful tip: Never clear the GPIO Interrupt Status by calling `bl_gpio_int_clear`...

```c
    //  Note: DO NOT Clear the GPIO Interrupt Status for the pin!
    //  This will suppress subsequent GPIO Interrupts!
    //  bl_gpio_int_clear(gpioPin, SET);
```

`bl_gpio_int_clear` causes __subsequent GPIO Interrupts to be suppressed__. So we should never call it!

We can't `printf` in an Interrupt Handler (for troubleshooting), but we can __increment some Interrupt Counters__ that will be displayed by the __`spi_result`__ command...

```c
    //  Increment the Interrupt Counters
    if (SX1276_DIO0 >= 0 && gpioPin == (uint8_t) SX1276_DIO0) { g_dio0_counter++; }
    //  Omitted: Increment Interrupt Counters
    //  for DIO1 to DIO4
    ...
    else if (SX1276_DIO5 >= 0 && gpioPin == (uint8_t) SX1276_DIO5) { g_dio5_counter++; }
    else { g_nodio_counter++; }
```

Next we add the Interrupt Event (with the Handler Function inside) to the __Event Queue__ (from the NimBLE Porting Layer)...

```c
    //  Use Event Queue to invoke Event Handler in the Application Task, 
    //  not in the Interrupt Context
    if (event != NULL && event->fn != NULL) {
        extern struct ble_npl_eventq event_queue;
        ble_npl_eventq_put(&event_queue, event);
    }
```

(In the next chapter we shall see the __Background Task__ that will receive the Event and process the received LoRa Packet)

We finish up by enabling the GPIO Interrupt for the pin...

```c
    //  Enable GPIO Interrupt for the pin
    bl_gpio_intmask(gpioPin, 0);
    return 0;
}
```

And that's how we handle GPIO Interrupts on BL602!

## Register Handlers for DIO0 to DIO5

_Earlier we registered the GPIO Handler Function for `DIO0`. What about `DIO1` to `DIO5`?_

Here's how we actually register the GPIO Handler Functions for `DIO0` to `DIO5`, in a single shot...

First we define the GPIO Pins for `DIO0` to `DIO5`: [`sx1276.h`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276.h#L48-L53)

```c
#define SX1276_DIO0        11  //  DIO0: Trigger for Packet Received
#define SX1276_DIO1         0  //  DIO1: Trigger for Sync Timeout
#define SX1276_DIO2         5  //  DIO2: Trigger for Change Channel (Spread Spectrum / Frequency Hopping)
#define SX1276_DIO3        12  //  DIO3: Trigger for CAD Done
#define SX1276_DIO4        -1  //  DIO4: Unused (FSK only)
#define SX1276_DIO5        -1  //  DIO5: Unused (FSK only)
```

Next we define the GPIO Handler Functions for `DIO0` to `DIO5`: [`sx1276.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L208-L213)

```c
//  DIO Handler Functions
DioIrqHandler *DioIrq[] = { 
    SX1276OnDio0Irq, SX1276OnDio1Irq,
    SX1276OnDio2Irq, SX1276OnDio3Irq,
    SX1276OnDio4Irq, NULL };  //  DIO5 not used for LoRa Modulation
```

Then we pass the DIO Handler Functions `DioIrq` to the function `SX1276IoIrqInit` defined in [`sx1276-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L144-L240)

```c
/// Register GPIO Interrupt Handlers for DIO0 to DIO5.
/// Based on hal_button_register_handler_with_dts in https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_button.c
void SX1276IoIrqInit(DioIrqHandler **irqHandlers) {

    //  DIO0: Trigger for Packet Received and Packet Transmitted
    if (SX1276_DIO0 >= 0 && irqHandlers[0] != NULL) {
        int rc = register_gpio_handler(       //  Register GPIO Handler...
            SX1276_DIO0,                  //  GPIO Pin Number
            irqHandlers[0],               //  GPIO Handler Function
            GLB_GPIO_INT_CONTROL_ASYNC,   //  Async Control Mode
            GLB_GPIO_INT_TRIG_POS_PULSE,  //  Trigger when GPIO level shifts from Low to High
            0,                            //  No pullup
            0                             //  No pulldown
        );
        assert(rc == 0);
    }
```

This is similar to the code we've seen earlier for registering the GPIO Handler Function for `DIO0`.

The code for `DIO1` to `DIO5` looks highly similar...

```c
    //  Omitted: Register GPIO Handler Functions
    //  for DIO1 to DIO4
    ...

    //  DIO5: Unused (FSK only)
    if (SX1276_DIO5 >= 0 && irqHandlers[5] != NULL) {
        int rc = register_gpio_handler(       //  Register GPIO Handler...
            SX1276_DIO5,                  //  GPIO Pin Number
            irqHandlers[5],               //  GPIO Handler Function
            GLB_GPIO_INT_CONTROL_ASYNC,   //  Async Control Mode
            GLB_GPIO_INT_TRIG_POS_PULSE,  //  Trigger when GPIO level shifts from Low to High
            0,                            //  No pullup
            0                             //  No pulldown
        );
        assert(rc == 0);
    }
```

To wrap up, we register the GPIO Interrupt Handler and enable GPIO Interrupts (as explained earlier)...

```c
    //  Register Common Interrupt Handler for GPIO Interrupt
    bl_irq_register_with_ctx(
        GPIO_INT0_IRQn,         //  GPIO Interrupt
        handle_gpio_interrupt,  //  Interrupt Handler
        NULL                    //  Argument for Interrupt Handler
    );

    //  Enable GPIO Interrupt
    bl_irq_enable(GPIO_INT0_IRQn);
}
```

That is all... We register the GPIO Handler Functions for `DIO0` to `DIO5` with a single call to `SX1276IoIrqInit`.

[(Our SX1276 Driver calls `SX1276IoIrqInit` here)](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L421-L458)

# Multitask with NimBLE Porting Layer

_Move Fast OR Break Things... Choose ONE!_

__Handling an interrupt__ gets tricky for any Embedded Program...

1.  __Interrupts are Time-Sensitive__: We can't take too long to handle an interrupt... Other interrupts may be waiting on us! 

    (Lag ensues)

1.  __No Blocking Input / Output__: Suppose our SX1276 Interrupt Handler needs to send an SPI Command to reset `DIO0`.

    That's no-no because our Interrupt Handler would block waiting for the SPI operation to complete. And hold up other interrupts.

1.  __No Console Output__: Troubleshooting an Interrupt Handler gets challenging because we can't show anything on the console (due to (1) and (2) above).

    (Also challenging: Handling errors in an Interrupt Handler)

Hence some chunks of our Interrupt Handling Logic would need to run inside a __higher-level, lower-priority Application Task__. Like this...

![Interrupt Handler vs Application Task](https://lupyuen.github.io/images/lora2-handler2.png)

Our Interrupt Handler (left) would need to signal the Application Task (right) to do some work.

_We'll do this with FreeRTOS, no?_

Let's do this with [__NimBLE Porting Layer__](https://lupyuen.github.io/pinetime-rust-mynewt/articles/dfu#nimble-stack-for-bluetooth-le-on-pinetime) instead.  It's a library of multitasking functions that's __portable to multiple operating systems__: FreeRTOS, Mynewt, NuttX, RIOT.

(And it looks simpler for folks who are new to FreeRTOS)

## Background Task

We start by creating the Background Task (right side of above pic) that will process the received LoRa Packets: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L253-L267)

```c
//  Create a FreeRTOS Task that runs task_callback
nimble_port_freertos_init(
    task_callback  //  Callback Function for the Task
);
```

We call __`nimble_port_freertos_init`__ (from the NimBLE Porting Layer) to start a FreeRTOS Background Task that runs the function `task_callback`.

The function __`task_callback`__ loops forever, doing work in the background...

```c
/// Task Function that works in the background
static void task_callback(void *arg) {
    //  Loop forever doing work
    for (;;) {
        ...
    }
}
```

Let's give it some work to do, by sending an Event...

![Event Queue](https://lupyuen.github.io/images/lora2-handler3.png)

## Event Queue

Our Background Task shall receive __Events__ from an __Event Queue__ and process them.

We define our Event and Event Queue like so: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L244-L248)

```c
/// Event Queue containing Events to be processed
struct ble_npl_eventq event_queue;

/// Event to be added to the Event Queue
struct ble_npl_event event;
```

To initialise the Event and Event Queue, we call __`ble_npl_event_init` and `ble_npl_eventq_init`__ like this: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L253-L267)

```c
/// Command to create a FreeRTOS Task with NimBLE Porting Layer
static void create_task(char *buf, int len, int argc, char **argv) {
    //  Init the Event Queue
    ble_npl_eventq_init(&event_queue);

    //  Init the Event
    ble_npl_event_init(
        &event,        //  Event
        handle_event,  //  Event Handler Function
        NULL           //  Argument to be passed to Event Handler
    );

    //  Create a FreeRTOS Task to process the Event Queue
    nimble_port_freertos_init(task_callback);
}
```

This call to __`ble_npl_event_init`__ says...

1.  When our Background Task __receives the Event__...

1.  __Execute the function `handle_event`__ to process the Event

Here's a bare-bones Event Handler: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L296-L299)

```c
/// Handle an Event
static void handle_event(struct ble_npl_event *ev) {
    printf("\r\nHandle an event\r\n");
}
```

__`handle_event`__ processes an Event by printing a message.

Later we'll see a more sophisticated Event Handler for processing received LoRa Packets.

## Send Event

To __send an Event__ into an Event Queue, we call __`ble_npl_eventq_put`__ like so: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L269-L273)

```c
/// Command to enqueue an Event into the Event Queue with NimBLE Porting Layer
static void put_event(char *buf, int len, int argc, char **argv) {
    //  Add the Event to the Event Queue
    ble_npl_eventq_put(
        &event_queue,  //  Event Queue
        &event         //  Event to be added to Event Queue
    );
}
```

Our Background Task will...

1.  Wake up

1.  Receive the Event

1.  Execute the Event Handler (`handle_event`)

We'll learn how in the next section.

_Is it OK to call this from an Interrupt Handler?_

Yep it's perfectly OK to call `ble_npl_eventq_put` from an Interrupt Handler.

In fact the implementation of `ble_npl_eventq_put` __differs slightly for Interupt Handlers vs Application Tasks__. [(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/npl_os_freertos.c#L59-L79)

This is another reason for calling NimBLE Porting Layer instead of FreeRTOS... NimBLE Porting Layer __handles the nitty-gritty__ on our behalf.

## Receive Event

Here's the code inside our Background Task that receives Events and executes the Event Handlers: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L275-L294)

```c
/// Task Function that dequeues Events from the Event Queue and processes the Events
static void task_callback(void *arg) {
    //  Loop forever handling Events from the Event Queue
    for (;;) {
        //  Get the next Event from the Event Queue
        struct ble_npl_event *ev = ble_npl_eventq_get(
            &event_queue,  //  Event Queue
            1000           //  Timeout in 1,000 ticks
        );

        //  If no Event due to timeout, wait for next Event
        if (ev == NULL) { continue; }
```

__`task_callback`__ loops forever, calling __`ble_npl_eventq_get`__ to receive Events from our Event Queue.

We've set a __timeout of 1,000 ticks__. (Yes it sounds arbitrary) If we don't receive an Event in 1,000 ticks, we loop and retry.

When we receive an Event...

1.  We call __`ble_npl_eventq_remove`__ to __remove the Event__ from the Event Queue

1.  Then we call __`ble_npl_event_run`__ to __execute the Event Handler__ (like `handle_event`)

```c
        //  Remove the Event from the Event Queue
        ble_npl_eventq_remove(&event_queue, ev);

        //  Trigger the Event Handler Function (handle_event)
        ble_npl_event_run(ev);
    }
}
```

And that's how we process an Event Queue with a Background Task!

_This Background Task looks so simple and generic... Will it work for all types of Events?_

Yes! Remember that we can __configure the Event Handler__ for our Event...

```c
//  Set the Event handler for the Event
ble_npl_event_init(   //  Init the Event for...
    ev,               //  Event
    handler,          //  Event Handler Function
    NULL              //  Argument to be passed to Event Handler
);
```

In the next section we'll learn to use __multiple Events__ (with different Event Handlers) to process LoRa Packets.

_Is there a way to test our Event Queue and Background Task?_

Yes, by sending a test Event. See this...

-   [__"Test Event Queue"__](https://lupyuen.github.io/articles/lora2#test-event-queue)

_Can we create multiple Background Tasks?_

Sorry we can't. Perhaps by modding NimBLE Porting Layer we can create multiple Background Tasks. [(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/nimble_port_freertos.c)

## LoRa Events

Earlier we have defined the __GPIO Handler Functions__ that will process the interrupts from our LoRa Transceiver (`DIO0` to `DIO5`)...

```c
//  DIO Handler Functions
DioIrqHandler *DioIrq[] = { 
    SX1276OnDio0Irq, SX1276OnDio1Irq,
    SX1276OnDio2Irq, SX1276OnDio3Irq,
    SX1276OnDio4Irq, NULL };  //  DIO5 not used for LoRa Modulation
```

_How shall we trigger these GPIO Handler Functions... From our GPIO Interrupt Handler?_

Easy: We use an __Array of Events__! From [`sx1276-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L405-L433)

```c
/// Maximum number of GPIO Pins that can be configured for interrupts
#define MAX_GPIO_INTERRUPTS 6  //  DIO0 to DIO5

/// Array of GPIO Pin Numbers that have been configured for interrupts
static uint8_t gpio_interrupts[MAX_GPIO_INTERRUPTS];

/// Array of Events for the GPIO Interrupts
static struct ble_npl_event gpio_events[MAX_GPIO_INTERRUPTS];
```

Our Event Array __`gpio_events`__ points to the GPIO Handler Functions (via the Event Handler)...

![GPIO Interrupts and Events](https://lupyuen.github.io/images/lora2-events.png)

As explained earlier, our GPIO Interrupt Handler calls __`enqueue_interrupt_event`__ to enqueue the Events from `gpio_events` into the Event Queue. [(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L435-L469)

_How are the arrays `gpio_interrupts` and `gpio_events` populated?_

We call __`init_interrupt_event`__ to initialise the `gpio_interrupts` and `gpio_events` arrays. [(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L471-L498)

## Timer

Remember that our LoRa SX1276 Transceiver will __listen 5 seconds for incoming packets__... Then we stop it to conserve battery power?

We do that with a __Callout Timer__ from the NimBLE Porting Layer. Here's how we __initialise a Callout Timer__: [`sx1276.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L227-L247)

```c
//  Define the Callout Timer
struct ble_npl_callout timer;

//  Init the Callout Timer with the Callback Function
ble_npl_callout_init(
    &timer,        //  Callout Timer
    &event_queue,  //  Event Queue that will handle the Callout upon timeout
    f,             //  Callback Function
    arg            //  Argument to be passed to Callback Function
);
```

When the Callout Timer expires, the Callback Function __`f`__ will be called by our Background Task (via the Event Queue).

Here's how we __set the Callout Timer__ to expire in `microsecs` microseconds: [`sx1276.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L264-L289)

```c
//  Assume that Callout Timer has been stopped.
//  Convert microseconds to ticks.
ble_npl_time_t ticks = ble_npl_time_ms_to_ticks32(
    microsecs / 1000  //  Duration in milliseconds
);

//  Wait at least 1 tick
if (ticks == 0) { ticks = 1; }

//  Trigger the Callout Timer after the elapsed ticks
ble_npl_error_t rc = ble_npl_callout_reset(
    &timer,  //  Callout Timer
    ticks    //  Number of ticks
);
assert(rc == 0);
```

To __stop a Callout Timer__ (and cancel the pending callback), we do this: [`sx1276.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L249-L262)

```c
//  If Callout Timer is still running...
if (ble_npl_callout_is_active(&timer)) {
    //  Stop the Callout Timer
    ble_npl_callout_stop(&timer);
}
```

Sometimes we need to suspend the current task and __wait a short while__. (Maybe to ponder our life choices) Here's how: [`sx1276.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L291-L307)

```c
//  Convert microseconds to ticks
ble_npl_time_t ticks = ble_npl_time_ms_to_ticks32(
    microsecs / 1000  //  Duration in milliseconds
);

//  Wait at least 1 tick
if (ticks == 0) { ticks = 1; }

//  Wait for the ticks
ble_npl_time_delay(ticks);
```

## Source Files

_How do we add the NimBLE Porting Layer to our own BL602 programs?_

Add the BL602 Library __`nimble-porting-layer`__ to the BL602 project as described here...

-   [__"How To Create BL602 Libraries"__](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-libraries)

Alternatively, copy these source files from the BL602 LoRa Firmware to your program...

1.  [__`nimble_npl.h`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/nimble_npl.h)

1.  [__`nimble_npl_os.h`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/nimble_npl_os.h)

1.  [__`nimble_port.h`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/nimble_port.h)

1.  [__`nimble_port_freertos.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/nimble_port_freertos.c)

1.  [__`nimble_port_freertos.h`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/nimble_port_freertos.h)

1.  [__`npl_freertos.h`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/npl_freertos.h)

1.  [__`npl_os_freertos.h`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/npl_os_freertos.c)

Be sure to __Enable Assertion Failure Messages__ by adding this function to `main.c` (or [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L324-L335))...

```c
/// TODO: We now show assertion failures in development.
/// For production, comment out this function to use the system default,
/// which loops forever without messages.
void __assert_func(const char *file, int line, const char *func, const char *failedexpr)
{
    //  Show the assertion failure, file, line, function name
	printf("Assertion Failed \"%s\": file \"%s\", line %d%s%s\r\n",
        failedexpr, file, line, func ? ", function: " : "",
        func ? func : "");
	//  Loop forever, do not pass go, do not collect $200
	for (;;) {}
}
```

The above source files were ported from the [__Apache NimBLE project__](https://github.com/apache/mynewt-nimble) with minor changes...

-   [Detect Interrupt Service Routine](https://github.com/lupyuen/bl_iot_sdk/commit/72e2cb44a40f9faf91c87ee8d421ed8eb4adb571#diff-c13b2cc976e41c4bc4d3fd967aefc40cccfb76bc14c7210001f675f371a14818)

-   [Rename `vPortEnterCritical` and `vPortExitCritical` to `taskENTER_CRITICAL` and `taskEXIT_CRITICAL`](https://github.com/lupyuen/bl_iot_sdk/commit/41a07867dceb5541439ff3f05129941647b9341f#diff-c13b2cc976e41c4bc4d3fd967aefc40cccfb76bc14c7210001f675f371a14818)

[(More about NimBLE Porting Layer)](https://lupyuen.github.io/pinetime-rust-mynewt/articles/dfu#nimble-stack-for-bluetooth-le-on-pinetime)

[(Why NimBLE Porting Layer feels right)](https://www.reddit.com/r/PINE64official/comments/mjt9vz/pinecone_bl602_riscv_board_receives_lora_packets/gtmk8tg?utm_source=share&utm_medium=web2x&context=3)

# Start the RAKwireless WisBlock Transmitter

Today we shall install __RAKwireless WisBlock__ to transmit LoRa Packets to BL602 for testing.

![RAKwireless WisBlock LPWAN Module mounted on WisBlock Base Board](https://lupyuen.github.io/images/wisblock-title.jpg)

_RAKwireless WisBlock LPWAN Module mounted on WisBlock Base Board_

## Connect WisBlock

Connect the following components according to the pic above...

1.  __WisBlock LPWAN Module__: This is the __Nordic nRF52840 Microcontroller__ with __Semtech SX1262 LoRa Transceiver__. [(More about this)](https://docs.rakwireless.com/Product-Categories/WisBlock/RAK4631/Overview/)

    Mount the LPWAN Module onto the WisBlock Base Board.

    (The LPWAN Module is already mounted when get the WisBlock Connected Box)

1.  __WisBlock Base Board__: This provides power to the LPWAN Module and exposes the USB and I/O ports. [(More about this)](https://docs.rakwireless.com/Product-Categories/WisBlock/RAK5005-O/Overview/)

    The LPWAN Module should be mounted on the Base Board.

1.  __LoRa Antenna__: Connect the LoRa Antenna to the LPWAN Module.

    (That's the black rod. Use the Antenna Adapter Cable)

1.  __Bluetooth LE Antenna__: Connect the Bluetooth LE Antenna to the LPWAN Module.

    (The stringy flappy thingy)

[__CAUTION: Always connect the LoRa Antenna and Bluetooth LE Antenna before Powering On... Or the LoRa and Bluetooth Transceivers may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

The above components are shipped in the [__WisBlock Connected Box__](https://store.rakwireless.com/products/wisblock-connected-box). (Which includes many more goodies!)

## Install VSCode and PlatformIO

1.  Follow the instructions in this excellent article to install __VSCode and PlatformIO__...

    -   [__Installation of Board Support Package in PlatformIO__](https://docs.rakwireless.com/Knowledge-Hub/Learn/Board-Support-Package-Installation-in-PlatformIO/)

1.  Remember to install the __LoRa Library `SX126x-Arduino`__ according to the steps above.

    (We may skip the LoRaWAN OTAA Example)

1.  Find out which __LoRa Frequency__ we should use for your region...

    -  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

    We'll set the LoRa Frequency in a while.

## Build the firmware

1.  Enter this at the command line...

    ```bash
    # Download the wisblock-lora-transmitter source code
    git clone --recursive https://github.com/lupyuen/wisblock-lora-transmitter
    ```

1.  In VSCode, click __`File → Open Folder`__

    Select the folder that we have just downloaded: __`wisblock-lora-transmitter`__

1.  Edit the file [__`src/main.cpp`__](https://github.com/lupyuen/wisblock-lora-transmitter/blob/main/src/main.cpp)

    Look for this code...

    ```c
    // Define LoRa parameters.
    // TODO: Change RF_FREQUENCY for your region
    #define RF_FREQUENCY 923000000  // Hz
    ```

    Change __`923`__ to the LoRa Frequency for your region: `434`, `780`, `868`, `915` or `923`

1.  Modify the __LoRa Parameters__ in [__`src/main.cpp`__](https://github.com/lupyuen/wisblock-lora-transmitter/blob/main/src/main.cpp) so that they match those in our BL602 LoRa Firmware

1.  __Build the LoRa Firmware__ by clicking the __`Build`__ icon at the lower left...

    ![Build Icon](https://lupyuen.github.io/images/wisblock-bar1.png)

1.  We should see this...

    ```text
    Processing wiscore_rak4631 (platform: nordicnrf52; board: wiscore_rak4631; framework: arduino)
    ...
    Building in release mode
    Checking size .pio/build/wiscore_rak4631/firmware.elf
    Advanced Memory Usage is available via "PlatformIO Home > Project Inspect"
    RAM:   [          ]   3.1% (used 7668 bytes from 248832 bytes)
    Flash: [=         ]   7.3% (used 59800 bytes from 815104 bytes)
    =========================== [SUCCESS] Took 4.49 seconds ===========================
    ```

    This WisBlock code is based on the (now obsolete) WisBlock LoRa Transmitter Example: [`LoRaP2P_TX.ino`](https://github.com/RAKWireless/WisBlock/blob/5082329327d723556e3613dc0eabcf399600a258/examples/communications/LoRa/LoRaP2P/LoRaP2P_TX/LoRaP2P_TX.ino)

## Flash the firmware

1.  __Connect WisBlock__ to our computer's USB port

1.  __Flash the LoRa Firmware__ to WisBlock by clicking the __`Upload`__ icon...

    ![Upload Icon](https://lupyuen.github.io/images/wisblock-bar2.png)

1.  We should see this...

    ![Firmware flashed successfully](https://lupyuen.github.io/images/wisblock-flash.png)

1.  If we see the message...

    ```text
    Timed out waiting for acknowledgement from device
    ```

    Then disconnect WisBlock from the USB port, reconnect and flash again.

    ![Firmware flashing failed](https://lupyuen.github.io/images/wisblock-flash2.png)

## Run the firmware

1.  __Run the LoRa Firmware__ by clicking the __`Monitor`__ icon...

    ![Monitor Icon](https://lupyuen.github.io/images/wisblock-bar3.png)

1.  We should see this...

    ```text
    > Executing task: platformio device monitor <
    --- Miniterm on /dev/cu.usbmodem14201  9600,8,N,1 ---
    --- Quit: Ctrl+C | Menu: Ctrl+T | Help: Ctrl+T followed by Ctrl+H ---
    ...
    OnTxDone
    OnTxDone
    OnTxDone
    ```

1.  WisBlock is now transmitting a LoRa Packet (`"Hello"`) every 5 seconds. [(See this)](https://github.com/lupyuen/wisblock-lora-transmitter/blob/main/src/main.cpp#L104-L128)

1.  If we sniff the airwaves with a __Software Defined Radio__, we will see the distinctive [__LoRa Chirp__](https://lupyuen.github.io/articles/lora#visualise-lora-with-software-defined-radio)...

    -   [__RAKwireless WisBlock​ LoRa​ Transmitter Sniffed by Airspy R2 SDR__](https://www.youtube.com/watch?v=USqStub3KC0)

# Build and Run the BL602 LoRa Firmware

Let's run the LoRa Demo Firmware for BL602 to receive the LoRa Packets transmitted by RAKwireless WisBlock.

Find out which __LoRa Frequency__ we should use for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Download the Firmware Binary File __`sdk_app_lora.bin`__ for your LoRa Frequency...

-  [__434 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.4)

-  [__780 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.5)

-  [__868 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.6)

-  [__915 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.7)

-  [__923 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.3)

Alternatively, we may build the Firmware Binary File `sdk_app_lora.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/lorarecv/customer_app/sdk_app_lora)...

```bash
# Download the lorarecv branch of lupyuen's bl_iot_sdk
git clone --recursive --branch lorarecv https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_lora

# TODO: Set the LoRa Frequency in sdk_app_lora/demo.c. 
# Edit the file and look for the line...
#   #define USE_BAND_923
# Change 923 to the LoRa Frequency for your region: 
#   434, 780, 868, 915 or 923 MHz
# See https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_lora.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`lorarecv`__ branch, not the default __`master`__ branch)

## Flash the firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_lora.bin` has been copied to the `blflash` folder.

Set BL602 to __Flashing Mode__ and restart the board...

__For PineCone:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash `sdk_app_lora.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_lora.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_lora.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

# For Windows: Change COM5 to the BL602 Serial Port
cargo run flash sdk_app_lora.bin --port COM5
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run the firmware

Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineCone:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602's UART Port at 2 Mbps like so...

__For Linux:__

```bash
sudo screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter LoRa commands

Let's enter some commands to transmit a LoRa Packet!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
    ====User Commands====
    create_task              : Create a task
    put_event                : Add an event
    init_driver              : Init LoRa driver
    send_message             : Send LoRa message
    receive_message          : Receive LoRa message
    read_registers           : Read registers
    spi_result               : Show SPI counters
    blogset                  : blog pri set level
    blogdump                 : blog info dump
    bl_sys_time_now          : sys time now
    ```

1.  First we __create the Background Task__ that will process received LoRa Packets.

    Enter this command...

    ```text
    # create_task
    ```

    This command calls the function `create_task`, which we have seen earlier.

1.  Then we __initialise our LoRa Transceiver__. 

    Enter this command...

    ```text
    # init_driver
    ```

    This command calls the function `init_driver`, which we have seen earlier.

1.  We should see this...

    ```text
    # init_driver
    SX1276 init
    SX1276 interrupt init
    SX1276 register handler: GPIO 11
    SX1276 register handler: GPIO 0
    SX1276 register handler: GPIO 5
    SX1276 register handler: GPIO 12
    ```

    This says that `register_gpio_handler` has __registered the GPIO Handler Functions__ for `DIO0` to `DIO3`. (`DIO4` and `DIO5` are unused)

    Our SX1276 Driver is now __listening for GPIO Interrupts__ and handling them.

1.  Then the __GPIO Interrupt for `DIO3`__ gets triggered automatically...

    ```text
    SX1276 DIO3: Channel activity detection    
    ```

    (We're not sure why this always happens when we initialise the driver... But it's harmless)

1.  Next we __receive a LoRa Packet__...

    ```text
    # receive_message
    ```

    This command calls the function `receive_message`, which we have seen earlier.

1.  We should see this...

    ```text
    # receive_message
    ...
    SX1276 DIO0: Packet received
    Rx done: RadioEvents.RxDone
    ```

    This says that the SX1276 Driver has __received a LoRa Packet.__

    And the packet contains `"Hello"`...

    ```text
    Rx done: 48 65 6c 6c 6f 
    ```

    (That's the ASCII code for `"Hello"`)

    [__Watch the receive video on YouTube__](https://youtu.be/3TSvo0dwwnQ)

    [__Check out the receive log__](https://gist.github.com/lupyuen/9bd7e7daa2497e8352d2cffec4be444d)

##  Receive Timeout

Remember that our SX1276 Transceiver will __listen 5 seconds for incoming packets__... Then it goes to sleep to conserve battery power?

Here's what happens when then SX1276 Driver doesn't receive any LoRa Packets within 5 seconds...

```text
# receive_message
...
SX1276 receive timeout
Rx timeout
```

Our __BL602 Timer is triggered automatically__ after 5 seconds to put the SX1276 Transceiver to sleep.

[__Watch the receive timeout video on YouTube__](https://www.youtube.com/watch?v=6qqZVcqN_rg)

[__Check out the receive timeout log__](https://gist.github.com/lupyuen/ce578fd561ca050d4680c1750984ffd4)

# Troubleshoot LoRa

_What could go wrong with our BL602 LoRa Receiver?_

Sorry to sound so down... But many things can go wrong with our BL602 LoRa Receiver!

Here's a __BL602 LoRa troubleshooting guide__...

![LoRa troubleshooting](https://lupyuen.github.io/images/lora2-troubleshoot.png)

1.  BL602 __not receiving__ any LoRa Packets?

    Sniff the airwaves with a __Spectrum Analyser or Software Defined Radio__. (See below)

1.  SX1276 __not responding__, or returning strange data?

    Verify the SPI Connection by __Reading the SX1276 Registers__. (See below)

1.  SX1276 __still not receiving__ LoRa Packets?

    Turn on __SPI Tracing__ and check the SPI Commands. (See below)

1.  SX1276 __not triggering interrupts__ when LoRa Packets are received?

    Check the __SX1276 Interrupt Counters__. (See below)

1.  Background Task __not processing the interrupts__?

    Test the __Event Queue__ by sending an Event. (See below)

1.  BL602 __hitting a RISC-V Exception__?

    Turn on __Stack Trace__. (See below)

1.  BL602 __Stack Trace not helpful__?

    Do a __Stack Dump__. (See below)

Let's go into the details.

## Sniff LoRa Packets

It helps to validate that the LoRa Packets that we're about to receive... Are __actually in the airwaves__!

Sniff the airwaves with a __Spectrum Analyser or Software Defined Radio__. Check that the LoRa Packets are centered at the right LoRa Frequency.

LoRa Packets have this distinctive shape, called a __LoRa Chirp__...

![LoRa Packet](https://lupyuen.github.io/images/lora-sdr5.png)

[__Watch the video on YouTube__](https://www.youtube.com/watch?v=USqStub3KC0)

More about sniffing LoRa Packets...

-   [__"Troubleshoot LoRa with Spectrum Analyser"__](https://lupyuen.github.io/articles/lora#troubleshoot-lora)

-   [__"Visualise LoRa with Software Defined Radio"__](https://lupyuen.github.io/articles/lora#visualise-lora-with-software-defined-radio)

## Read Registers

Verify the SPI Connection between BL602 and SX1276 by entering the command __`read_registers`__...

```text
# read_registers
Register 0x02 = 0x1a
Register 0x03 = 0x0b
Register 0x04 = 0x00
Register 0x05 = 0x52
```

This command reads the SX1276 Registers over the SPI Connections.

If there's a fault in the SPI wiring, we will see incorrect register values.

More about `read_registers`...

-   [__"Troubleshoot LoRa with read_registers"__](https://lupyuen.github.io/articles/lora#troubleshoot-lora)

## Trace SPI Requests

To enable SPI Tracing:

1.  Edit [`components/hal_drv/ bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/fe9bbabdddb05fc4961b8f52784305046a413505/components/hal_drv/bl602_hal/hal_spi.c#L57)

1.  Set __`HAL_SPI_DEBUG`__ to __`(1)`__ like so...

    ```c
    //  Enable SPI Tracing
    #define HAL_SPI_DEBUG (1)
    ```

1.  Rebuild the firmware: `make clean` then `make`

We will see all SPI DMA Requests sent by BL602 to SX1276...

```text
hal_spi_transfer = 1
transfer xfer[0].len = 1
Tx DMA src=0x4200cc58, dest=0x4000a288, size=1, si=1, di=0, i=1
Rx DMA src=0x4000a28c, dest=0x4200cc54, size=1, si=0, di=1, i=1
recv all event group.
```

More about SPI Tracing messages...

-   [__"Run LoRa Firmware with SPI Tracing"__](https://lupyuen.github.io/articles/lora#enter-lora-commands)

## Show Interrupt Counters

We may check the number of GPIO and SPI Interrupts triggered by SX1276 by entering the __`spi_result`__ command...

```text
# spi_result
DIO0 Interrupts: 1
DIO3 Interrupts: 1
Tx Interrupts:   302
Rx Interrupts:   302
```

This demo video explains the Interrupt Counters...

-   [__Watch the receive video on YouTube__](https://youtu.be/3TSvo0dwwnQ)

-   [__Check out the receive log__](https://gist.github.com/lupyuen/9bd7e7daa2497e8352d2cffec4be444d)

## Test Event Queue

To check whether our Event Queue and Background Task (from the NimBLE Porting Layer) are OK, do this...

1.  If the Background Task has NOT been started, enter this command...

    ```text
    # create_task
    ```

    (`create_task` should only be run once)

1.  Then enter this command to enqueue an Event into our Event Queue...

    ```text
    # put_event
    ```

1.  We should see this...

    ```text
    Handle an event
    ```

    This means that our Event Queue and Background Task are ready to handle Interrupt Events triggered by SX1276.

## BL602 Stack Trace

When our BL602 Firmware hits an Exception, we'll see a message like this...

```text
Exception Entry--->>>
mcause 38000001, mepc 00000000, mtval 00000000
Exception code: 1
  msg: Instruction access fault
```

This is not really helpful because it doesn't show the Stack Trace: The function calls leading to the Exception.

To show the Stack Trace, edit the Makefile `proj_config.mk` (like  [`sdk_app_lora/proj_config.mk`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/proj_config.mk#L40-L43)) and add this...

```text
# Show Stack Trace when we hit a RISC-V Exception, 
# by enabling the Stack Frame Pointer.
# After setting this flag, do "make clean ; make"
CONFIG_ENABLE_FP:=1
```

Rebuild the firmware: __`make clean`__ then __`make`__.

When BL602 hits an Exception, we'll see this Stack Trace:

```text
=== backtrace start ===
backtrace_stack: frame pointer=0x42011e70
backtrace: 0x2300ba88 (@ 0x42011e6c)
backtrace: 0x2300a852 (@ 0x42011e9c)
backtrace: 0x00000004   <--- TRAP
backtrace: INVALID!!!
=== backtrace end ===
```

[(View the complete log)](https://gist.github.com/lupyuen/5ddbcdd1054c775521291c3d114f6cee)

This shows the function calls leading to the Exception, so it's more helpful for troubleshooting.

To find the source code that corresponds to the program address (like `0x2300ba88`), follow the instructions here to generate the __RISC-V Disassembly File__...

-   [__"How to Troubleshoot RISC-V Exceptions"__](https://lupyuen.github.io/articles/i2c#appendix-how-to-troubleshoot-risc-v-exceptions)

## BL602 Stack Dump

For some types of BL602 Exceptions, the Stack Trace doesn't appear to be meaningful.

(The Stack Trace points to the BL602 Exception Handler, not to the code that caused the Exception)

For such Exceptions, we need to __dump the stack ourselves__ and analyse the trail of calls.

Here's the function that dumps the stack: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L471-L490)

```c
/// Dump the current stack
void dump_stack(void)
{
    //  For getting the Stack Frame Pointer. Must be first line of function.
    uintptr_t *fp;

    //  Fetch the Stack Frame Pointer. Based on backtrace_riscv from
    //  https://github.com/bouffalolab/bl_iot_sdk/blob/master/components/bl602/freertos_riscv_ram/panic/panic_c.c#L76-L99
    __asm__("add %0, x0, fp" : "=r"(fp));
    printf("dump_stack: frame pointer=%p\r\n", fp);

    //  Dump the stack, starting at Stack Frame Pointer - 1
    printf("=== stack start ===\r\n");
    for (int i = 0; i < 128; i++) {
        uintptr_t *ra = (uintptr_t *)*(unsigned long *)(fp - 1);
        printf("@ %p: %p\r\n", fp - 1, ra);
        fp++;
    }
    printf("=== stack end ===\r\n\r\n");
}
```

We call __`dump_stack`__ in the BL602 Exception Handler like this: [`bl_irq.c`](https://github.com/lupyuen/bl_iot_sdk/blob/ee4a10b1a1e3609243bd5e7b3a45f02d768f6c14/components/hal_drv/bl602_hal/bl_irq.c#L316-L341)

```c
//  Declare dump_stack
void dump_stack(void);

//  BL602 Exception Handler
void exception_entry(uint32_t mcause, uint32_t mepc, uint32_t mtval, uintptr_t *regs) {
        ...
        //  Show exception and stack trace
        __dump_exception_code_str(mcause & 0xFFFF);
        backtrace_now((int (*)(const char *fmt, ...))printf, regs);

        //  Dump the stack here
        printf("Exception Handler Stack:\r\n"); 
        dump_stack();

        while (1) { /*Deap loop now*/ }
```

When BL602 hits an Exception, we'll see this Stack Dump...

```text
Exception Handler Stack:
dump_stack: frame pointer=0x42011e70
=== stack start ===
...
@ 0x42011f20: 0x00000000
@ 0x42011f24: 0x00000000
@ 0x42011f28: 0x42011f50
@ 0x42011f2c: 0x23000cd2 <--
@ 0x42011f30: 0x04000000
@ 0x42011f34: 0x00000001
@ 0x42011f38: 0x4000a28c
```

[(View the complete log)](https://gist.github.com/lupyuen/5ddbcdd1054c775521291c3d114f6cee)

After a big chunk of nulls (omitted from above) we see a meaningful address...

```text
0x23000cd2
```

This address points to code that actually caused the Exception.

[(We forgot to initialise the stack variable `radio_events`... ALWAYS INITIALISE STACK VARIABLES!)](https://twitter.com/MisterTechBlog/status/1374577517214851077)

[(Analysis of the Stack Dump)](https://twitter.com/MisterTechBlog/status/1374545090731855872)

Perhaps someday we shall fix the BL602 Stack Trace so that it displays the right program addresses...

-   [__Source Code for BL602 Stack Trace: `backtrace_riscv`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/freertos_riscv_ram/panic/panic_c.c#L75-L99)

-   [__How we use GCC Stack Frame Pointers to navigate the BL602 Stack__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/freertos_riscv_ram/panic/panic_c.c#L8-L49)

## BL602 Assertion Failures

Be sure to __Enable Assertion Failure Messages__ by adding this function to `main.c` (or [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorarecv/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L324-L335))...

```c
/// TODO: We now show assertion failures in development.
/// For production, comment out this function to use the system default,
/// which loops forever without messages.
void __assert_func(const char *file, int line, const char *func, const char *failedexpr)
{
    //  Show the assertion failure, file, line, function name
	printf("Assertion Failed \"%s\": file \"%s\", line %d%s%s\r\n",
        failedexpr, file, line, func ? ", function: " : "",
        func ? func : "");
	//  Loop forever, do not pass go, do not collect $200
	for (;;) {}
}
```

Comment out this function when building the production firmware.

![Sketching LoRa](https://lupyuen.github.io/images/lora2-sketch.jpg)

# What's Next

We have completed __Level One__ of our epic quest for the [__Three Levels of LoRa__](https://lupyuen.github.io/articles/lora#lora-vs-lorawan)!

Let's move on to __LoRa Levels Two and Three__...

1.  We shall install a __LoRaWAN Gateway__ and join BL602 to __The Things Network__

    -   [__"Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway"__](https://lupyuen.github.io/articles/wisgate)

1.  But before that, we shall port the __LoRaWAN Driver from Apache Mynewt OS to BL602__

    -   [__"PineCone BL602 Talks LoRaWAN"__](https://lupyuen.github.io/articles/lorawan)

1.  And before that, we shall clean up and reorganise the __library files for NimBLE and SX1276__

    -   [__"How To Create BL602 Libraries"__](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-libraries)

So eventually we shall build __LoRaWAN Sensor Devices with BL602__!

We have come a loooong way since I first [__experimented with LoRa in 2016__](https://github.com/lupyuen/LoRaArduino)...

- __Cheaper Transceivers__: Shipped overnight from Thailand!

- __Mature Networks__: LoRaWAN, The Things Network

- __Better Drivers__: Thanks to Apache Mynewt OS!

- __Powerful Microcontrollers__: Arduino Uno vs RISC-V BL602

- __Awesome Tools__: RAKwireless WisBlock, Airspy SDR, RF Explorer

Now is the __right time to build LoRa gadgets.__ Stay tuned for more LoRa and LoRaWAN Adventures!

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/mjt99m/pinecone_bl602_riscv_board_receives_lora_packets/?utm_source=share&utm_medium=web2x&context=3)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lora2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lora2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1370708936739885056?s=20)

# Appendix: How To Create BL602 Projects

Follow these steps to create a new BL602 Project (like `sdk_app_lorawan`)...

1.  __Copy the Project Folder__ for an existing Project, like `sdk_app_lora`...

    -   [__Project Folder for `sdk_app_lora`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_lora)

1.  __Paste the Project Folder__ into __`bl_iot_sdk/customer_app`__ and rename it (like `sdk_app_lorawan`)...

    ![BL602 Project](https://lupyuen.github.io/images/lora2-app.png)

    Be sure to __rename the Sub Folder__ too. (The `sdk_app_lorawan` inside `sdk_app_lorawan`)

    __Delete the `build_out` folder__ if it exists.

1.  __Edit the `Makefile`__ in the new folder and set the Project Name: [`sdk_app_lorawan/Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/Makefile)

    ```text
    #  Set the project name
    PROJECT_NAME := sdk_app_lorawan
    ```

1.  Set the __GCC Compiler Options__ in the `Makefile` (if any): [`sdk_app_lorawan/Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/Makefile)

    ```text
    # Define the GCC compiler options

    # Set LoRa Region to 1 (AS923). See components/3rdparty/lorawan/include/node/lora_band.h
    CFLAGS += -DCONFIG_LORA_NODE_REGION=1

    # Do not auto-join the LoRaWAN Network
    CFLAGS += -DLORA_APP_AUTO_JOIN=0
    ```

1.  __For macOS Only__: Edit the __`run.sh` script__ in the new folder and set the Project Name: [`sdk_app_lorawan/run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/run.sh)

    ```bash
    #  Set the project name
    export APP_NAME=sdk_app_lorawan
    ```

1.  __Build the project__ by entering these commands...

    ```bash
    # TODO: Change this to the full path of bl_iot_sdk
    export BL60X_SDK_PATH=$HOME/bl_iot_sdk
    export CONFIG_CHIP_NAME=BL602

    # TODO: Change sdk_app_lorawan to the project name
    cd bl_iot_sdk/customer_app/sdk_app_lorawan
    make
    ```

1.  __For macOS Only__: We may build, flash and run the new firmware with the `run.sh` script instead...

    ```bash
    # TODO: Change sdk_app_lorawan to the project name
    cd bl_iot_sdk/customer_app/sdk_app_lorawan

    # TODO Before Flashing: Switch GPIO 8 to Flashing Mode. Restart the BL602 board.

    # Build, flash and run the firmware (with CoolTerm)
    ./run.sh

    # TODO After Flashing: Switch GPIO 8 to Normal Mode. Restart the BL602 board.
    ```

1.  Remember to edit the __README.md file__ and fill in the project details

# Appendix: How To Create BL602 Libraries

We're now refactoring the LoRa Firmware Source Code from this article to create __reusable BL602 Libraries__...

1.  [__BL602 Library for LoRa SX1276 Driver__](https://github.com/lupyuen/bl_iot_sdk/tree/master/components/3rdparty/lora-sx1276)

1.  [__BL602 Library for NimBLE Porting Layer__](https://github.com/lupyuen/bl_iot_sdk/tree/master/components/3rdparty/nimble-porting-layer)

To create your own BL602 Library...

1.  Place the source files into a new folder under [__`bl_iot_sdk/components/3rdparty`__](https://github.com/lupyuen/bl_iot_sdk/tree/master/components/3rdparty)

    Here's where we created the folder for NimBLE Porting Layer...

    ![BL602 Library](https://lupyuen.github.io/images/lora2-library.png)

1.  In the folder, create two subfolders...

    - __`include`__: For the include files (`*.h`)

    - __`src`__: For the source files (`*.c`)

1.  In the same folder, create the file [__`bouffalo.mk`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/3rdparty/nimble-porting-layer/bouffalo.mk) containing...

    ```text

    # Component Makefile
    #

    # Include Folders
    COMPONENT_ADD_INCLUDEDIRS := include

    # Object Files (*.o)
    COMPONENT_OBJS := $(patsubst %.c,%.o, $(COMPONENT_SRCS))

    # Source Folders
    COMPONENT_SRCDIRS := src
    ```

1.  In the same folder, create the file [__`component.mk`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/3rdparty/nimble-porting-layer/component.mk) containing...

    ```text
    #
    # Component Makefile
    #

    # Include Folders
    COMPONENT_ADD_INCLUDEDIRS := include

    # Source Folders
    COMPONENT_SRCDIRS := src

    # Check the submodule is initialised
    COMPONENT_SUBMODULES := 
    ```

1.  If there are multiple Include Folders or Source Folders, add them to __`COMPONENT_ADD_INCLUDEDIRS` and `COMPONENT_SRCDIRS`__ in the above two files. Like so...

    -   [__AWS IoT `bouffalo.mk`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/3rdparty/aws-iot/bouffalo.mk)

    -   [__AWS IoT `component.mk`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/3rdparty/aws-iot/component.mk)

How do we reference the BL602 Library in our BL602 Project?

1.  Edit the __`Makefile`__ for our BL602 Project (like `sdk_app_lora/Makefile`)

1.  Look for the __`INCLUDE_COMPONENTS`__ section.

    Insert a new `INCLUDE_COMPONENTS` line that specifies the names of the BL602 Libraries to be used.

    So to use the BL602 Libraries `lora-sx1276` and `nimble-porting-layer`, we would insert this line...

    ```text
    INCLUDE_COMPONENTS += lora-sx1276 nimble-porting-layer
    ```

1.  To look neater, the `Makefile` for our LoRa Firmware defines a variable `COMPONENTS_LORA` like so: [`sdk_app_lora/Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_lora/Makefile)

    ```text
    # Added this line to define COMPONENTS_LORA...
    COMPONENTS_LORA    := lora-sx1276 nimble-porting-layer
    COMPONENTS_BLSYS   := bltime blfdt blmtd bloop loopadc looprt loopset
    COMPONENTS_VFS     := romfs
    COMPONENTS_BLE     := 

    INCLUDE_COMPONENTS += freertos_riscv_ram bl602 bl602_std hal_drv vfs yloop utils cli blog blog_testc
    INCLUDE_COMPONENTS += easyflash4
    INCLUDE_COMPONENTS += $(COMPONENTS_NETWORK)
    INCLUDE_COMPONENTS += $(COMPONENTS_BLSYS)
    INCLUDE_COMPONENTS += $(COMPONENTS_VFS)
    # Added this line to reference COMPONENTS_LORA...
    INCLUDE_COMPONENTS += $(COMPONENTS_LORA)
    INCLUDE_COMPONENTS += $(PROJECT_NAME)
    ```

![Pinebook Pro keeping me company during vaccination (Moderna)... Because bringing a PineCone would look so odd 👍](https://lupyuen.github.io/images/lora2-vaccine.jpg)

_Pinebook Pro keeping me company during vaccination (Moderna)... Because bringing a PineCone would look so odd 👍_
