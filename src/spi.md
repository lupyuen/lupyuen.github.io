# PineCone BL602 talks SPI too!

📝 _10 Feb 2021_

Here's the source code for BL602 accessing BME280 over SPI: [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c)

In this article we'll study the source code and look into these issues with BL602 SPI...

1.  The pins for __Serial Data In__ and __Serial Data Out__ seem to be flipped, when observed with a Logic Analyser. 

    This contradicts the BL602 Reference Manual.

1.  To talk to BME280, we must configure BL602 for __SPI Polarity 0, Phase 1__.

    Though the Logic Analyser shows that it looks like SPI Phase 0.

1.  BL602's __SPI Chip Select Pin__ doesn't work with BME280's SPI protocol.

    We'll control the SPI Chip Select Pin ourselves.

1.  Setting __Serial Data Out to Pin 0__ will switch on the WiFi LED.

    We'll switch to a different pin for Serial Data Out.

Also we'll learn to __troubleshoot BL602 SPI with a Logic Analyser__.

![PineCone BL602 RISC-V Board connected to BME280 SPI Sensor](https://lupyuen.github.io/images/spi-title.jpg)

_PineCone BL602 RISC-V Board connected to BME280 SPI Sensor_

# Times Are a-Changin'

Humans evolve... So do the terms that we use!

This article will become obsolete quickly unless we adopt the [__new names for SPI Pins__](https://www.oshwa.org/a-resolution-to-redefine-spi-signal-names)...

-  We'll say __"Serial Data In"__ _(instead of "MISO")_

-  And we'll say __"Serial Data Out"__ _(instead of "MOSI")_

-  We'll refer to BL602 as the __"SPI Controller"__

-  And BME280 as the __"SPI Peripheral"__

Note that Serial Data In and Serial Data Out are flipped across the SPI Controller and the SPI Peripheral...

-  __Serial Data In on BL602__ connects to __Serial Data Out on BME280__

-  And __Serial Data Out on BL602__ connects to __Serial Data In on BME280__

(Yep it works like the Transmit / Receive pins for a UART port)

# BL602 Hardware Abstraction Layer for SPI

TODO

# Connect BL602 to BME280 SPI Sensor

TODO

# Initialise SPI Port

TODO

[`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L45-L100)

```c
/// Use SPI Port Number 0
#define SPI_PORT   0

/// Use GPIO 14 as SPI Chip Select Pin
#define SPI_CS_PIN 14

/// SPI Port
static spi_dev_t spi;

/// Init the SPI Port
static void test_spi_init(char *buf, int len, int argc, char **argv)
{
    //  Configure the SPI Port
    //  Note: The Chip Select Pin below (2) must NOT be the same as SPI_CS_PIN (14). 
    //  Because the SPI Pin Function will override the GPIO Pin Function!

    //  TODO: The pins for Serial Data In and Serial Data Out seem to be flipped,
    //  when observed with a Logic Analyser. This contradicts the 
    //  BL602 Reference Manual. Why ???

    //  TODO: We must set Polarity=0, Phase=1. Though the Logic Analyser shows
    //  that it looks like Phase=0. Why ???

    //  TODO: Setting Serial Data Out to Pin 0 will switch on the WiFi LED.
    //  Why ???

    int rc = spi_init(
        &spi,        //  SPI Device
        SPI_PORT,    //  SPI Port
        0,           //  SPI Mode: 0 for Controller (formerly Master), 1 for Peripheral (formerly Slave)
        1,           //  SPI Polar Phase: 0 (CPOL=0, CPHA=0), 1 (CPOL=0, CPHA=1), 2 (CPOL=1, CPHA=0) or 3 (CPOL=1, CPHA=1)
        200 * 1000,  //  SPI Frequency (200 kHz)
        2,   //  Transmit DMA Channel
        3,   //  Receive DMA Channel
        3,   //  (Yellow) SPI Clock Pin 
        2,   //  (Unused) SPI Chip Select Pin (Unused because we control GPIO 14 ourselves as Chip Select Pin. This must NOT be set to 14, SPI will override our GPIO!)
        1,   //  (Green)  SPI Serial Data In Pin  (formerly MISO)
        4    //  (Blue)   SPI Serial Data Out Pin (formerly MOSI)
    );
    assert(rc == 0);

    //  Configure Chip Select pin as a GPIO Pin
    GLB_GPIO_Type pins[1];
    pins[0] = SPI_CS_PIN;
    BL_Err_Type rc2 = GLB_GPIO_Func_Init(GPIO_FUN_SWGPIO, pins, sizeof(pins) / sizeof(pins[0]));
    assert(rc2 == SUCCESS);

    //  Configure Chip Select pin as a GPIO Output Pin (instead of GPIO Input)
    rc = bl_gpio_enable_output(SPI_CS_PIN, 0, 0);
    assert(rc == 0);

    //  Set Chip Select pin to High, to deactivate BME280
    printf("Set CS pin %d to high\r\n", SPI_CS_PIN);
    rc = bl_gpio_output_set(SPI_CS_PIN, 1);
    assert(rc == 0);
}
```

# Transmit SPI Data

TODO

[`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L110-L156)

```c
/// Start the SPI data transfer
static void test_spi_transfer(char *buf, int len, int argc, char **argv)
{
    //  Clear the buffers
    memset(&tx_buf1, 0, sizeof(tx_buf1));
    memset(&rx_buf1, 0, sizeof(rx_buf1));
    memset(&tx_buf2, 0, sizeof(tx_buf2));
    memset(&rx_buf2, 0, sizeof(rx_buf2));

    //  Prepare 2 SPI Transfers
    static spi_ioc_transfer_t transfers[2];
    memset(transfers, 0, sizeof(transfers));    

    //  First SPI Transfer: Transmit Register ID (0xD0) to BME280
    tx_buf1[0] = 0xd0;  //  Read BME280 Chip ID Register (0xD0). Read/Write Bit (High Bit) is 1 for Read.
    transfers[0].tx_buf = (uint32_t) tx_buf1;  //  Transmit Buffer (Register ID)
    transfers[0].rx_buf = (uint32_t) rx_buf1;  //  Receive Buffer
    transfers[0].len    = sizeof(tx_buf1);     //  How many bytes

    //  Second SPI Transfer: Receive Chip ID (0x60) from BME280
    tx_buf2[0] = 0xff;  //  Unused. Read/Write Bit (High Bit) is 1 for Read.
    transfers[1].tx_buf = (uint32_t) tx_buf2;  //  Transmit Buffer
    transfers[1].rx_buf = (uint32_t) rx_buf2;  //  Receive Buffer (Chip ID)
    transfers[1].len    = sizeof(tx_buf2);     //  How many bytes

    //  Set Chip Select pin to Low, to activate BME280
    printf("Set CS pin %d to low\r\n", SPI_CS_PIN);
    int rc = bl_gpio_output_set(SPI_CS_PIN, 0);
    assert(rc == 0);

    //  Execute the two SPI Transfers with the DMA Controller
    rc = hal_spi_transfer(
        &spi,       //  SPI Device
        transfers,  //  SPI Transfers
        sizeof(transfers) / sizeof(transfers[0])  //  How many transfers (Number of requests, not bytes)
    );
    assert(rc == 0);

    //  DMA Controller will transmit and receive the SPI data in the background.
    //  hal_spi_transfer will wait for the two SPI Transfers to complete before returning.
    //  Now that we're done with the two SPI Transfers...

    //  Set Chip Select pin to High, to deactivate BME280
    rc = bl_gpio_output_set(SPI_CS_PIN, 1);
    assert(rc == 0);
    printf("Set CS pin %d to high\r\n", SPI_CS_PIN);
}
```

# Receive SPI Data

TODO

# Show the Results

TODO

[`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L158-L182)

```c
/// Show the SPI data received and the interrupt counters
static void test_spi_result(char *buf, int len, int argc, char **argv)
{
    //  Show the received data
    printf("SPI Transfer #1: Received Data 0x%p:\r\n", rx_buf1);
    for (int i = 0; i < sizeof(rx_buf1); i++) {
        printf("  %02x\r\n", rx_buf1[i]);
    }
    printf("SPI Transfer #2: Received Data 0x%p:\r\n", rx_buf2);
    for (int i = 0; i < sizeof(rx_buf2); i++) {
        printf("  %02x\r\n", rx_buf2[i]);
    }

    //  Show the Interrupt Counters, Status and Error Codes defined in components/hal_drv/bl602_hal/hal_spi.c
    extern int g_tx_counter, g_rx_counter;
    extern uint32_t g_tx_status, g_tx_tc, g_tx_error, g_rx_status, g_rx_tc, g_rx_error;
    printf("Tx Interrupts: %d\r\n",   g_tx_counter);
    printf("Tx Status:     0x%x\r\n", g_tx_status);
    printf("Tx Term Count: 0x%x\r\n", g_tx_tc);
    printf("Tx Error:      0x%x\r\n", g_tx_error);
    printf("Rx Interrupts: %d\r\n",   g_rx_counter);
    printf("Rx Status:     0x%x\r\n", g_rx_status);
    printf("Rx Term Count: 0x%x\r\n", g_rx_tc);
    printf("Rx Error:      0x%x\r\n", g_rx_error);
}
```

# Build and Run the Firmware

TODO

```text
# help
====Build-in Commands====
====Support 4 cmds once, seperate by ; ====
help                     : print this
p                        : print memory
m                        : modify memory
echo                     : echo for command
exit                     : close CLI
devname                  : print device name
sysver                   : system version
reboot                   : reboot system
poweroff                 : poweroff system
reset                    : system reset
time                     : system time
ota                      : system ota
ps                      : thread dump
ls                       : file list
hexdump                  : dump file
cat                      : cat file

====User Commands====
spi_init                 : Init SPI port
spi_transfer             : Transfer SPI data
spi_result               : Show SPI data received
blogset                  : blog pri set level
blogdump                 : blog info dump
bl_sys_time_now          : sys time now

# spi_init
port0 eventloop init = 42010b48
[HAL] [SPI] Init :
port=0, mode=0, polar_phase = 1, freq=200000, tx_dma_ch=2, rx_dma_ch=3, pin_clk=3, pin_cs=2, pin_mosi=1, pin_miso=4
set rwspeed = 200000
hal_gpio_init: cs:2, clk:3, mosi:1, miso: 4
hal_gpio_init: SPI controller mode
hal_spi_init.
Set CS pin 14 to high

# spi_transfer
Set CS pin 14 to low
hal_spi_transfr = 2
transfer xfer[0].len = 1
Tx DMA src=0x4200d1b8, dest=0x4000a288, size=1, si=1, di=0, i=1
Rx DMA src=0x4000a28c, dest=0x4200d1b0, size=1, si=0, di=1, i=1
recv all event group.
transfer xfer[1].len = 1
Tx DMA src=0x4200d1bc, dest=0x4000a288, size=1, si=1, di=0, i=1
Rx DMA src=0x4000a28c, dest=0x4200d1b4, size=1, si=0, di=1, i=1
recv all event group.
Set CS pin 14 to high

# spi_result
SPI Transfer #1: Received Data 0x0x4200d1b0:
  ff
SPI Transfer #2: Received Data 0x0x4200d1b4:
  60
Tx Interrupts: 2
Tx Status:     0x0
Tx Term Count: 0x0
Tx Error:      0x0
Rx Interrupts: 2
Rx Status:     0x0
Rx Term Count: 0x0
Rx Error:      0x0
```

# Port BL602 SPI HAL to other Operating Systems

TODO

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/spi.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/spi.md)

# Appendix: Test BME280 with Bus Pirate

TODO

# Appendix: Troubleshoot BL602 SPI with Logic Analyser

TODO
