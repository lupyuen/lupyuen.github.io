# SPI on Apache NuttX OS

📝 _12 Dec 2021_

![PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left)](https://lupyuen.github.io/images/spi2-title.jpg)

_PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left)_

Last article we explored __Apache NuttX OS__ and its __GPIO Functions__...

-   [__"Apache NuttX OS on RISC-V BL602 and BL604"__](https://lupyuen.github.io/articles/nuttx)

Today we shall venture into the __SPI Functions__ and discover...

-   How to __transmit and receive__ data over SPI

-   By coding a simple NuttX __Device Driver__

-   And testing with __Semtech SX1262__ (LoRa Transceiver)

-   On Bouffalo Lab's __BL602 and BL604__ RISC-V SoCs

We'll also study briefly the internals of the __NuttX SPI Driver__, to understand how it works.

_What about ESP32? NuttX works the same across platforms right?_

I realise that many of my readers are using ESP32 instead of BL602.

In this article I'll point out the tweaks needed to __run the code on ESP32__.

(Watch for the __"Xref"__ tags)

![SPI Test App calls SPI Test Driver to access SPI Driver](https://lupyuen.github.io/images/spi2-plan.jpg)

# SPI Test App and Driver

_(For BL602 and ESP32)_

Our plan for today (pic above)...

1.  We create an __SPI Test App__ that will transfer data over SPI.

    (A tiny program with a few lines of code)

1.  We create an __SPI Test Driver__ (called by SPI Test App) that will handle the SPI Operations.

    (To transmit and receive data over SPI)

1.  Our SPI Test Driver exposes a NuttX [__Character Device Interface__](https://nuttx.apache.org/docs/latest/components/drivers/character/index.html): open(), write(), read() and close().

    (Yep it looks like Linux, because NuttX is POSIX Compliant)

1.  Our SPI Test Driver executes the SPI Operations by calling the __BL602 or ESP32 SPI Driver__.

    (Which is equivalent to the Hardware Abstraction Layer in other operating systems)

_This looks complex. Is there a simpler way?_

Yes we have options for doing __SPI on NuttX__...

1.  If our SPI Device is supported by an __existing NuttX Device Driver__, just go ahead and use the driver!

    [(Browse the NuttX Device Drivers)](https://github.com/apache/incubator-nuttx/tree/master/drivers)

1.  If we're transferring data over SPI __for testing only__ (not for a real app), we may call the [__SPI Transfer Interface__](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/spi/spi_transfer.h)

    [(Here's how... It's complicated)](https://github.com/apache/incubator-nuttx-apps/blob/master/system/spi)

1.  But today we experiment with a __Custom Device Driver__ that will talk to our own SPI Device.

    That's why we're building the __SPI Test Driver__.

    (Eventually we'll build a LoRaWAN Driver for Semtech SX1262)

_Can our app call the BL602 / ESP32 SPI Driver directly?_

Nope that's not supported by NuttX. (Unlike other embedded operating systems)

It might seemingly work on BL602 and ESP32, but it will fail on platforms with __Memory Protection__.

(Imagine a Linux App directly calling a Kernel Driver... That's no-no!)

Later we'll see the layers of code that abstract the BL602 / ESP32 SPI Driver from our NuttX App.

[(Thanks to Alan Carvalho de Assis for the tip!)](https://www.linkedin.com/feed/update/urn:li:activity:6871062176673742848/?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A6871062176673742848%2C6871868918772846592%29&replyUrn=urn%3Ali%3Acomment%3A%28activity%3A6871062176673742848%2C6871912576393986048%29)

_Must everything be done through the read() and write() interfaces?_

There's another POSIX Interface that's supported by NuttX: __ioctl()__.

We'll see this when we cover the NuttX Device Driver for Semtech SX1276.

![SPI Test Driver](https://lupyuen.github.io/images/spi2-plan2.jpg)

# Inside the SPI Test Driver

_(For BL602 and ESP32)_

Let's study the code in our __SPI Test Driver__...

-   [__drivers/rf/spi_test_driver.c__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c)

    [(Header File)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/include/nuttx/rf/spi_test_driver.h)

We created the SPI Test Driver by cloning another device driver, as explained here...

-   [__"Create a NuttX Device Driver"__](https://lupyuen.github.io/articles/spi2#appendix-create-a-nuttx-device-driver)

In the following sections we explain the SPI features that we have implemented in the driver.

![File operations implemented by our driver](https://lupyuen.github.io/images/spi2-driver2a.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L80-L89)

## File Operations

Every [__NuttX Character Device Driver__](https://nuttx.apache.org/docs/latest/components/drivers/character/index.html) defines a list of supported __File Operations__...

-   __open()__: Open the driver

-   __close()__: Close the driver

-   __read()__: Read data

-   __write()__: Write data

-   __ioctl()__: Other operations

(Plus others: seek(), poll(), ...)

Our driver defines the File Operations like so: [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L88-L97)

```c
static const struct file_operations g_spi_test_driver_fops =
{
  spi_test_driver_open,
  spi_test_driver_close,
  spi_test_driver_read,
  spi_test_driver_write,
  NULL,  /* Seek not implemented */
  spi_test_driver_ioctl,
  NULL   /* Poll not implemented */
};

/* In spi_test_driver_register() we register the character driver */

register_driver(
  devpath, 
  &g_spi_test_driver_fops, 
  0666, 
  priv);
```

__spi_test_driver_register()__ and __register_driver()__ are called during NuttX Startup, as explained here...

-   [__"Register Device Driver"__](https://lupyuen.github.io/articles/spi2#register-device-driver)

Our driver implements the __write()__ and __read()__ operations to transfer data over SPI.

(They will be called by our __SPI Test App__, as we'll see later)

_SPI is a full-duplex protocol. How will we implement read() and write()?_

To simplify our SPI Test Driver, the __read operation shall be buffered__...

1.  __write()__ transmits the provided data over SPI

1.  And saves the received data into the __Receive Buffer__

1.  Then __read()__ returns the received data from the __Receive Buffer__

The __Receive Buffer__ is defined like so: [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L99-L101)

```c
static char recv_buffer[256];  /* Buffer for SPI response */

static int recv_buffer_len = 0;  /* Length of SPI response */
```

Let's dive into the write() and read() operations.

## Write Operation

In the write() operation for our SPI Test Driver, we...

1.  __Lock__ the SPI Bus

1.  __Configure__ the SPI Interface

1.  __Select__ the SPI Device

1.  __Transfer__ SPI Data

1.  __Deselect__ the device and __unlock__ the bus

Below is the implementation: [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L168-L208)

```c
/* Write the buffer to the SPI device */

static ssize_t spi_test_driver_write(
  FAR struct file *filep,
  FAR const char *buffer,
  size_t buflen)
{
  DEBUGASSERT(buflen <= sizeof(recv_buffer));  /* TODO: Range eheck */
  DEBUGASSERT(buffer != NULL);
  DEBUGASSERT(filep  != NULL);

  /* Get the SPI interface */

  FAR struct inode *inode = filep->f_inode;
  DEBUGASSERT(inode != NULL);
  FAR struct spi_test_driver_dev_s *priv = inode->i_private;
  DEBUGASSERT(priv != NULL);
```

We begin by fetching the __SPI Interface__ from the File Struct.

Next we __lock the SPI Bus__ and __configure the SPI Interface__...

```c
  /* Lock the SPI bus and configure the SPI interface */

  DEBUGASSERT(priv->spi != NULL);
  SPI_LOCK(priv->spi, true);
  spi_test_driver_configspi(priv->spi);
```

(We'll see __spi_test_driver_configspi__ in a while)

We __select the SPI Device__ by pulling SPI Chip Select to Low...

```c
  /* Select the SPI device (unused for BL602) */

  SPI_SELECT(priv->spi, priv->spidev, true);
```

(This has no effect on BL602. The SPI Hardware automatically sets Chip Select to Low during SPI transfer)

Then we __transfer the data__ over SPI (transmit and receive)...

```c
  /* Transmit buffer to SPI device and receive the response */

  SPI_EXCHANGE(priv->spi, buffer, recv_buffer, buflen);
  recv_buffer_len = buflen;
```

Note that the received data goes into our __Receive Buffer__.

(Which will be returned in the read() operation)

Finally we __deselect the device__ and __unlock the bus__...

```c
  /* Deselect the SPI device (unused for BL602) */

  SPI_SELECT(priv->spi, priv->spidev, false);

  /* Unlock the SPI bus */

  SPI_LOCK(priv->spi, false);

  return buflen;
}
```

The return value is the number of bytes transferred.

(Deselect has no effect on BL602. The SPI Hardware automatically sets Chip Select to High after SPI transfer)

_What are SPI_LOCK, SPI_SELECT and SPI_EXCHANGE?_

That's the __SPI Interface__ for NuttX. We'll cover this in the Appendix.

![Write Operation](https://lupyuen.github.io/images/spi2-driver2.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L168-L208)

## Read Operation

Remember that the write() operation has saved the received SPI data into the __Receive Buffer__.

Thus for the read() operation we simply return the data in the Receive Buffer: [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L210-L233)

```c
/* Return the data received from the SPI device */

static ssize_t spi_test_driver_read(
  FAR struct file *filep, 
  FAR char *buffer,
  size_t buflen)
{
  DEBUGASSERT(filep  != NULL);
  DEBUGASSERT(buffer != NULL);

  /* Copy the SPI response to the buffer */

  DEBUGASSERT(recv_buffer_len >= 0);
  DEBUGASSERT(recv_buffer_len <= buflen);  /* TODO: Range check */
  memcpy(buffer, recv_buffer, recv_buffer_len);

  /* Return the number of bytes read */

  return recv_buffer_len;
}
```

## Configure SPI

Earlier we called __spi_test_driver_configspi__ to configure the SPI Interface.

Below is the implementation: [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L107-L129)

```c
static inline void spi_test_driver_configspi(FAR struct spi_dev_s *spi)
{
  DEBUGASSERT(spi != NULL);

  /* Set SPI Mode (Polarity and Phase) and Transfer Size (8 bits) */

  SPI_SETMODE(spi, SPI_TEST_DRIVER_SPI_MODE);
  SPI_SETBITS(spi, 8);

  /* Set SPI Hardware Features and Frequency */

  SPI_HWFEATURES(spi, 0);
  SPI_SETFREQUENCY(spi, CONFIG_SPI_TEST_DRIVER_SPI_FREQUENCY);
}
```

(SPI_SETMODE, SPI_SETBITS, SPI_HWFEATURES and SPI_SETFREQUENCY are defined in the NuttX SPI Interface)

The code above configures the SPI Interface as follows...

-   __SPI Mode__ (Polarity Phase): 0

    (For BL602 we're using Mode 1)

-   __SPI Transfer Size__: 8 bits

-   __SPI Hardware Features__: None

-   __SPI Frequency__: 1 MHz

__SPI Mode__ and __SPI Frequency__ are defined below: [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L45-L57)

```c
/* We set SPI Frequency to 1 MHz */

#ifndef CONFIG_SPI_TEST_DRIVER_SPI_FREQUENCY
#define CONFIG_SPI_TEST_DRIVER_SPI_FREQUENCY 1000000
#endif /* CONFIG_SPI_TEST_DRIVER_SPI_FREQUENCY */

/* For BL602 we use SPI Mode 1 instead of Mode 0 due to SPI quirk */

#ifdef CONFIG_BL602_SPI0
#define SPI_TEST_DRIVER_SPI_MODE (SPIDEV_MODE1) /* SPI Mode 1: Workaround for BL602 */
#else
#define SPI_TEST_DRIVER_SPI_MODE (SPIDEV_MODE0) /* SPI Mode 0: CPOL=0,CPHA=0 */
#endif /* CONFIG_BL602_SPI0 */
```

BL602 uses __SPI Mode 1__ (instead of Mode 0) because of an __SPI Mode Quirk__ in BL602. 

(More about this in the Appendix)

![Register SPI Test Driver at startup](https://lupyuen.github.io/images/spi2-newdriver4.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L599-L617)

# Load the SPI Test Driver

_(For BL602 and ESP32)_

_How do we load our SPI Test Driver at startup?_

During NuttX Startup, we __load our SPI Test Driver__ like so: [bl602_bringup.c](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L599-L617)

```c
int bl602_bringup(void)
{
  ...
#ifdef CONFIG_RF_SPI_TEST_DRIVER

  /* Init SPI bus again */

  struct spi_dev_s *spitest = bl602_spibus_initialize(0);
  if (!spitest)
    {
      _err("ERROR: Failed to initialize SPI %d bus\n", 0);
    }

  /* Register the SPI Test Driver */

  ret = spi_test_driver_register("/dev/spitest0", spitest, 0);
  if (ret < 0)
    {
      _err("ERROR: Failed to register SPI Test Driver\n");
    }

#endif /* CONFIG_RF_SPI_TEST_DRIVER */
```

[__bl602_bringup__](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L367-L620) is the NuttX Startup Function for BL602.

([__esp32_bringup__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c#L118-L426) for ESP32)

We modified the Startup Function to __register our SPI Test Driver__, which loads the driver into NuttX at startup.

Let's run NuttX on BL602 / ESP32 and check that our __SPI Test Driver loads correctly__...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the modified source code...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone --branch spi_test https://github.com/lupyuen/incubator-nuttx nuttx
    git clone --branch spi_test https://github.com/lupyuen/incubator-nuttx-apps apps
    ```

1.  Configure the build...

    ```bash
    cd nuttx

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Edit the Build Config
    make menuconfig 
    ```

1.  Enable the SPI Peripheral and SPI Character Driver in menuconfig...

    [__"Enable SPI"__](https://lupyuen.github.io/articles/spi2#enable-spi)

    ![Enable SPI](https://lupyuen.github.io/images/spi2-debug.png)

1.  Enable our SPI Test Driver...

    [__"Enable SPI"__](https://lupyuen.github.io/articles/spi2#enable-spi)

    ![Select SPI Test Driver](https://lupyuen.github.io/images/spi2-newdriver6.png)

1.  Enable SPI logging for easier troubleshooting...

    [__"Enable Logging"__](https://lupyuen.github.io/articles/spi2#enable-logging)

    ![Enable logging](https://lupyuen.github.io/images/spi2-driver4.png)

1.  Save the configuration and exit menuconfig

1.  For ESP32: Edit [__esp32_bringup.c__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c#L118-L426) to register our SPI Test Driver [(See this)](https://lupyuen.github.io/articles/spi2#register-device-driver)

1.  Build ("make"), flash and run the NuttX Firmware on BL602 or ESP32

1.  In the NuttX Shell, enter...

    ```bash
    ls /dev
    ```

    Our SPI Test Driver appears as __"/dev/spitest0"__
    
    ![Our SPI Test Driver appears as "/dev/spitest0"](https://lupyuen.github.io/images/spi2-newdriver10.png)

    Congratulations NuttX has loaded our Device Driver!

    Let's talk about our SPI Test App.

![SPI Test App](https://lupyuen.github.io/images/spi2-plan3.jpg)

# Inside the SPI Test App

_(For BL602 and ESP32)_

We've seen the write() and read() operations in our SPI Test Driver.  Now we learn how they are called by our __SPI Test App__...

-   [__examples/spi_test__](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test)

We created the SPI Test App by cloning another app, as explained here...

-   [__"Create a NuttX App"__](https://lupyuen.github.io/articles/spi2#appendix-create-a-nuttx-app)

We'll do the following in our SPI Test App...

1.  __Open__ our SPI Test Driver

1.  __Transmit__ data over SPI

1.  __Receive__ data over SPI

1.  __Close__ our SPI Test Driver

## Open SPI Test Driver

Earlier we saw that our SPI Test Driver appears in NuttX as __"/dev/spitest0"__

Let's open the driver: [spi_test_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test/spi_test_main.c)

```c
int main(int argc, FAR char *argv[])
{
  /* Open SPI Test Driver */

  int fd = open("/dev/spitest0", O_RDWR);
  assert(fd >= 0);  /* TODO: Handle error */
```

(Yep this looks very Linux-like!)

__open()__ returns a __File Descriptor__ that we'll use to transmit and receive data over SPI.

## Transmit SPI Data

Our SPI Test Driver implements a __write()__ operation that will transmit SPI data.

We call it like so...

```c
  /* Write to SPI Test Driver */

  static char data[] = "Hello World";
  int bytes_written = write(fd, data, sizeof(data));
  assert(bytes_written == sizeof(data));
```

This transmits the string __"Hello World"__ to our SPI Device.

(Including the terminating null character)

## Receive SPI Data

Remember that the __write()__ operation will actually transmit and receive SPI data at the same time.

We read the received SPI data by calling __read()__...

```c
  /* Read response from SPI Test Driver */

  static char rx_data[256];  /* Buffer for SPI response */
  int bytes_read = read(fd, rx_data, sizeof(rx_data));
  assert(bytes_read == sizeof(get_status));
```

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L65-L69)

This code isn't in our SPI Test App, we'll see this later when we test with Semtech SX1262.

## Close SPI Test Driver

Finally we close the File Descriptor for our SPI Test Driver...

```c
  /* Close SPI Test Driver */

  close(fd);
  return 0;
}
```

Let's run our SPI Test App!

![SPI Test App](https://lupyuen.github.io/images/spi2-app4.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test/spi_test_main.c)

# Run the SPI Test App

_(For BL602 and ESP32)_

Follow these steps to run our SPI Test App on BL602 or ESP32...

1.  Assume that we have downloaded and configured our NuttX code...

    [__"Load the SPI Test Driver"__](https://lupyuen.github.io/articles/spi2#load-the-spi-test-driver)

1.  Edit the build configuration...

    ```bash
    make menuconfig
    ```

1.  Enable our SPI Test App in menuconfig...

    [__"Enable App"__](https://lupyuen.github.io/articles/spi2#enable-app)

    ![Enable SPI Test App in menuconfig](https://lupyuen.github.io/images/spi2-newapp4.png)

1.  Save the configuration and exit menuconfig

1.  Build ("make"), flash and run the NuttX Firmware on BL602 or ESP32

1.  In the NuttX Shell, enter...

    ```bash
    spi_test
    ```

1.  We should see every byte transmitted and received over SPI.

    (Thanks to SPI Logging!)

    The pic below shows that our app has transmitted the string __"Hello World"__ (plus the terminating null) over SPI.

    But because we're not connected to any SPI Device, we don't receive any meaningful response. (It's all `0xFF`)

    ![SPI Test App](https://lupyuen.github.io/images/spi2-app3.png)

# Test with Logic Analyser

_(For BL602 and ESP32)_

_How do we check if our app is transmitting SPI data correctly?_

Let's connect a __Logic Analyser__ to BL602 / ESP32 and verify the SPI output...

Logic Analyser | BL602 Pin | ESP32 Pin
:-------: | :---------: | :--------:
__MOSI__ | GPIO 1 | GPIO 13
__MISO__ | GPIO 0 | GPIO 12
__SCK__  | GPIO 3 | GPIO 14
__CS__   | GPIO 2 | GPIO 15
__GND__  | GND | GND

![Logic Analyser connected to PineCone BL602](https://lupyuen.github.io/images/spi2-logic4.jpg)

_How did we get the GPIO Pin Numbers for the SPI Port?_

__For BL602:__ SPI Pins are defined in [board.h](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/risc-v/bl602/bl602evb/include/board.h#L87-L92)

```c
#define BOARD_SPI_CS   (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN2)
#define BOARD_SPI_MOSI (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN1)
#define BOARD_SPI_MISO (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN0)
#define BOARD_SPI_CLK  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN3)
```

__For ESP32:__ SPI Pins are defined in [Kconfig](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/xtensa/src/esp32/Kconfig#L799-L817)

```text
config ESP32_SPI2_CSPIN
	int "SPI2 CS Pin"
	default 15
	range 0 39

config ESP32_SPI2_CLKPIN
	int "SPI2 CLK Pin"
	default 14
	range 0 39

config ESP32_SPI2_MOSIPIN
	int "SPI2 MOSI Pin"
	default 13
	range 0 39

config ESP32_SPI2_MISOPIN
	int "SPI2 MISO Pin"
	default 12
	range 0 39
```

When we run __"spi_test"__, we see this in our Logic Analyser...

![Running spi_test and observing the Logic Analyser](https://lupyuen.github.io/images/spi2-logic2.png)

This looks OK! Though MISO is idle because it's not connected to an SPI Device.

Let's test with a real SPI Device: Semtech SX1262.

(BL602 has a quirk that swaps MISO and MOSI, the fix is explained in the Appendix)

# Control Chip Select with GPIO

_(For BL602 and ESP32)_

If we zoom out the display in the Logic Analyser, we see a problem with __SPI Chip Select on BL602__...

![Chip Select goes Low after every byte](https://lupyuen.github.io/images/spi2-logic3.png)

BL602 sets Chip Select to __High after EVERY byte__!

This will be a problem for __Semtech SX1262__...

It expects Chip Select to be __High after the entire multi-byte command__ has been transmitted! (Not after every byte)

(I don't think ESP32 has this problem, please lemme know! 🙏)

_Can we control SPI Chip Select ourselves?_

TODO

![](https://lupyuen.github.io/images/spi2-sx5.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L42-L74)

# Test with Semtech SX1262

_(For BL602 and ESP32)_

TODO

Let's test #NuttX SPI with #BL602 and Semtech SX1262 LoRa Transceiver

[(Source)](https://www.semtech.com/products/wireless-rf/lora-core/sx1262)

![](https://lupyuen.github.io/images/spi2-title.jpg)

TODO60

Our #NuttX App transmits an SPI Command to SX1262 ... And reads the SPI Response from SX1262

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L54-L84)

![](https://lupyuen.github.io/images/spi2-sx4.png)

TODO62

Now our #NuttX App is ready to read an SX1262 Register over SPI!

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L90-L119)

![](https://lupyuen.github.io/images/spi2-sx6.png)

TODO58

Our #NuttX App reads an SX1262 Register ... But it returns garbage! There's a workaround for this #BL602 SPI Quirk

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L90-L119)

![](https://lupyuen.github.io/images/spi2-sx2.png)

TODO63

#BL602 has an SPI Quirk ... We must use SPI Mode 1 instead of Mode 0 ... Let's fix this in #NuttX

[(Source)](https://lupyuen.github.io/articles/spi#spi-phase-looks-sus)

For #NuttX on #BL602, we use SPI Mode 1 instead of Mode 0 ... To work around the SPI Mode Quirk

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L51-L57)

![](https://lupyuen.github.io/images/spi2-sx7.png)

TODO57

Our #NuttX App now reads the SX1262 Register correctly! 🎉

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c)

![](https://lupyuen.github.io/images/spi2-sx.png)

# Test with PineDio Stack

_(For BL604 only)_

TODO

Will #NuttX run on #Pine64's PineDio Stack BL604 with onboard Semtech SX1262? Let's find out!

[(Source)](https://lupyuen.github.io/articles/pinedio)

![](https://lupyuen.github.io/images/spi2-pinedio.jpg)

TODO55

Here's how Semtech SX1262 is wired onboard #PineDio Stack #BL604 ... Let's update the Pin Definitions in NuttX

![](https://lupyuen.github.io/images/spi2-pinedio3.png)

TODO53

Here are the #NuttX Pin Definitions for PineDio Stack BL604 with onboard SX1262 ... As derived from the schematic

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L42-L95)

![](https://lupyuen.github.io/images/spi2-pinedio.png)

TODO54

Our #NuttX App runs OK on PineDio Stack BL604 with onboard SX1262! 🎉

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c)

![](https://lupyuen.github.io/images/spi2-pinedio2.png)


# What's Next

TODO

I'm new to NuttX but I had lots of fun experimenting with it. I hope you'll enjoy NuttX too!

Here are some topics I might explore in future articles, lemme know if I should do these...

-   __SPI Driver__: PineDio Stack BL604 has an onboard LoRa SX1262 Transceiver wired via SPI. Great way to test the NuttX SPI Driver for BL602 / BL604!

    [(More about PineDio Stack BL604)](https://lupyuen.github.io/articles/lorawan2)

-   __LoRaWAN Driver__: Once we get SX1262 talking OK on SPI, we can port the LoRaWAN Driver to NuttX!

    [(LoRaWAN on PineDio Stack BL604)](https://lupyuen.github.io/articles/lorawan2)

-   __Rust__: Porting the Embedded Rust HAL to NuttX sounds really interesting. We might start with GPIO and SPI to see whether the concept is feasible.

(BL602 IoT SDK / FreeRTOS is revamping right now to the [__new "hosal" HAL__](https://twitter.com/MisterTechBlog/status/1456259223323508748). Terrific time to explore NuttX now!)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/spi2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/spi2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1464898624026906625)

# Appendix: Create a NuttX Device Driver

_(For BL602 and ESP32)_

This section explains the steps to create a __NuttX Device Driver__ named __"spi_test_driver"__.

(Change "spi_test_driver" to the desired name of our driver)

1.  Browse to the [__"nuttx/nuttx/drivers/rf"__](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf) folder

1.  Copy the file __"dat-31r5-sp.c"__ and paste it as __"spi_test_driver.c"__

    ![Copy "dat-31r5-sp.c" to "spi_test_driver.c"](https://lupyuen.github.io/images/spi2-newdriver.png)

    [(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/spi_test_driver.c)

1.  Inside the __"spi_test_driver.c"__ file, search and replace all __"dat31r5sp"__ by __"spi_test_driver"__

    Be sure to __Preserve Case!__

    ![Change all "dat31r5sp" to "spi_test_driver"](https://lupyuen.github.io/images/spi2-newdriver2.png)

    [(Source)](https://github.com/lupyuen/incubator-nuttx/commit/8fee69215163180b77dc9d5b9e7449ebe00ac1cc)

1.  Browse to the [__"nuttx/nuttx/include/nuttx/rf"__](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/include/nuttx/rf) folder

1.  Copy the file __"dat-31r5-sp.h"__ and paste it as __"spi_test_driver.h"__

1.  Inside the __"spi_test_driver.h"__ file, search and replace all __"dat31r5sp"__ by __"spi_test_driver"__

    Remember to __Preserve Case!__

    The Header File should look like this...

    ![spi_test_driver.h](https://lupyuen.github.io/images/spi2-newdriver3.png)

    [(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/include/nuttx/rf/spi_test_driver.h)

## Update Makefile and Kconfig

Now we update the Makefile so that NuttX will build our Device Driver...

1.  Browse to the [__"nuttx/nuttx/drivers/rf"__](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf) folder

1.  Edit the file __"Make.defs"__

    Insert this section...

    ```text
    ifeq ($(CONFIG_RF_SPI_TEST_DRIVER),y)
      CSRCS += spi_test_driver.c
      RFDEPPATH = --dep-path rf
      RFVPATH = :rf
    endif
    ```

    As shown below...

    ![Update "Make.defs"](https://lupyuen.github.io/images/spi2-newdriver9.png)

    [(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/Make.defs#L33-L37)

1.  Edit the file __"Kconfig"__

    Insert this section...

    ```text
    config RF_SPI_TEST_DRIVER
        bool "SPI Test Driver"
        default n
        select SPI
        ---help---
            Enable SPI Test Driver.
    ```

    As shown below...

    ![Update "Kconfig"](https://lupyuen.github.io/images/spi2-newdriver5.png)

    [(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/Kconfig#L22-L27)

1.  Enter the following...

    ```bash
    ## TODO: Change this to the path of our "incubator-nuttx" folder
    cd nuttx/nuttx

    ## Preserve the Build Config
    cp .config ../config

    ## Erase the Build Config and Kconfig files
    make distclean

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Restore the Build Config
    cp ../config .config

    ## Edit the Build Config
    make menuconfig 
    ```

## Enable SPI

We enable SPI and our Device Driver as follows...

1.  In __menuconfig__, select __"System Type"__

    For BL602: Check the box for __"BL602 Peripheral Support"__ → __"SPI0"__

    For ESP32: Check the box for __"ESP32 Peripheral Select"__ → __"SPI 2"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

    ![Enable SPI](https://lupyuen.github.io/images/spi2-debug.png)

1.  At the Top Menu, select __"Device Drivers"__

    Select __"SPI Driver"__

    Check the box for __"SPI Character Driver"__

    (__"SPI Exchange"__ should already be checked, see pic above)

    Hit __"Exit"__ to return to "Device Drivers"

1.  Under "Device Drivers", check the box for __"RF Device Support"__

    Go inside __"RF Device Support"__

    Check the box for __"SPI Test Driver"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

    ![Select SPI Test Driver](https://lupyuen.github.io/images/spi2-newdriver6.png)

## Enable Logging

Next we enable SPI logging for easier troubleshooting...

1.  In __menuconfig__, select __"Build Setup"__ → __"Debug Options"__ 

1.  Check the boxes for the following...

    ```text
    Enable Debug Features
    Enable Error Output
    Enable Warnings Output
    Enable Informational Debug Output
    Enable Debug Assertions
    GPIO Debug Features
    GPIO Error Output
    GPIO Warnings Output
    GPIO Informational Output
    SPI Debug Features
    SPI Error Output
    SPI Warnings Output
    SPI Informational Output
    ```

    (See pic below)

1.  Hit __"Save"__ then __"OK"__ to save the NuttX Configuration to __".config"__

1.  Hit __"Exit"__ until __menuconfig__ quits

    ![Enable logging](https://lupyuen.github.io/images/spi2-driver4.png)

## Register Device Driver

During NuttX startup, we need to register our Device Driver like so...

1.  Browse to the __Board Folder__...

    For BL602: [__nuttx/nuttx/boards/ risc-v/bl602/bl602evb__](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src) 

    For ESP32: [__nuttx/nuttx/boards/ xtensa/esp32/esp32-devkitc__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src)

    (Change "esp32-devkitc" to our ESP32 board)

1.  Edit the __Bringup Code__...

    For BL602: [__bl602_bringup.c__](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L599-L617)

    For ESP32: [__esp32_bringup.c__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c#L118-L426)

1.  Edit the function __bl602_bringup()__ to register our Device Driver as __"/dev/spitest0"__...

    ```c
    /* Insert this code after the #include block */

    #ifdef CONFIG_RF_SPI_TEST_DRIVER
    #include <nuttx/rf/spi_test_driver.h>
    #endif /* CONFIG_RF_SPI_TEST_DRIVER */

    /* End of inserted code */

    ...

    int bl602_bringup(void)
    {
      /* Omitted: Existing code in the function */

      /* Insert this code just before the "return" statement */

    #ifdef CONFIG_RF_SPI_TEST_DRIVER

      /* Init SPI bus again */

      struct spi_dev_s *spitest = bl602_spibus_initialize(0);
      if (!spitest)
        {
          _err("ERROR: Failed to initialize SPI %d bus\n", 0);
        }

      /* Register the SPI Test Driver */

      ret = spi_test_driver_register("/dev/spitest0", spitest, 0);
      if (ret < 0)
        {
          _err("ERROR: Failed to register SPI Test Driver\n");
        }

    #endif /* CONFIG_RF_SPI_TEST_DRIVER */

      /* End of inserted code */

      return ret;
    }
    ```

    [(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L599-L617)

    [(See the changes)](https://github.com/lupyuen/incubator-nuttx/commit/4cae36747314bacb49ff0bba3632fbb8136f3f66#diff-387529ed7b85b38e4e96d58de6cab8a83e706c26c97e9fc71db5ea5ff20be297)

    For ESP32: Edit the function [__esp32_bringup()__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c#L118-L426) and insert the code above. Change __"bl602_spibus_initialize"__ to __"esp32_spibus_initialize"__. [(Like this)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/common/src/esp32_board_spidev.c#L47-L72)

    ![Register our device driver at startup](https://lupyuen.github.io/images/spi2-newdriver4.png)

## Verify Device Driver

Finally we run the NuttX Firmware and check for our Device Driver...

1.  Build ("make"), flash and run the NuttX Firmware on BL602 or ESP32.

1.  In the NuttX Shell, enter...

    ```bash
    ls /dev
    ```

    Our Device Driver appears as __"/dev/spitest0"__.
    
    Congratulations our Device Driver is now running on NuttX!

    ![Our Device Driver appears as "/dev/spitest0"](https://lupyuen.github.io/images/spi2-newdriver10.png)

1.  Look what happens if we forget to enable "SPI0" (BL602) or "SPI 2" (ESP32) and NuttX won't start...

    ![NuttX fails to start if we don't enable SPI](https://lupyuen.github.io/images/spi2-crash2.png)

    [(Source)](https://gist.github.com/lupyuen/ccfd90125f9a180b4cfb459e8a57b323)

_Why did we choose the "dat-31r5-sp" driver for cloning?_

We scanned the NuttX SPI Device Drivers ("grep" and "wc") and picked __"dat-31r5-sp"__ because...

1.  The driver code is __simple__

    (No dependencies on other modules)

1.  It has the __fewest lines of code__

    (Easier to customise)

1.  It's the __only driver__ in the RF Category

    (Quick to modify the Makefile and Kconfig)

Remember to move our driver to the correct category before releasing it!

![dat-31r5-sp is the simplest smallest SPI Device Driver](https://lupyuen.github.io/images/spi2-interface7.png)

[(Source)](https://docs.google.com/spreadsheets/d/1MDps5cPe7tIgCL1Cz98iVccJAUJq1lgctpKgg9OwztI/edit#gid=0)

# Appendix: Create a NuttX App

_(For BL602 and ESP32)_

This section explains the steps to create a __NuttX App__ named __"spi_test"__.

(Change "spi_test" to the desired name of our app)

1.  Browse to the [__"nuttx/apps/examples"__](https://github.com/lupyuen/incubator-nuttx-apps/tree/newapp/examples) folder

1.  Copy the __"hello"__ subfolder and paste it as __"spi_test"__

    ![Copy the "hello" subfolder and paste it as "spi_test"](https://lupyuen.github.io/images/spi2-newapp.png)

    [(Source)](https://github.com/lupyuen/incubator-nuttx-apps/commit/9af4ad6cab225d333ce0dae98c65a2a48621b3b4)

1.  Inside the __"spi_test"__ folder, rename __"hello_main.c"__ to __"spi_test_main.c"__

    ![Rename "hello_main.c" to "spi_test_main.c"](https://lupyuen.github.io/images/spi2-newapp2.png)

    [(Source)](https://github.com/lupyuen/incubator-nuttx-apps/commit/a4f884c67dc4c1042831d0554aed1d55a0e28b40)


1.  Inside the __"spi_test"__ folder, search and replace all __"hello"__ by __"spi_test"__

    Be sure to __Preserve Case!__

    ![Change all "hello" to "spi_test"](https://lupyuen.github.io/images/spi2-newapp3.png)

    [(Source)](https://github.com/lupyuen/incubator-nuttx-apps/commit/0e19613b3059882f002eee948c0a79f622eccb74)

    [(See "spi_test" folder)](https://github.com/lupyuen/incubator-nuttx-apps/tree/newapp/examples/spi_test)

1.  Enter the following...

    ```bash
    ## TODO: Change this to the path of our "incubator-nuttx" folder
    cd nuttx/nuttx

    ## Preserve the Build Config
    cp .config ../config

    ## Erase the Build Config and Kconfig files
    make distclean

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Restore the Build Config
    cp ../config .config

    ## Edit the Build Config
    make menuconfig 
    ```

    ![Select "spi_test" in menuconfig](https://lupyuen.github.io/images/spi2-newapp4.png)

## Enable App

Next we enable our app (pic above)...

1.  In __menuconfig__, select __"Application Configuration"__ → __"Examples"__

1.  Check the box for __"spi_test"__

1.  Hit __"Save"__ then __"OK"__ to save the NuttX Configuration to __".config"__

1.  Hit __"Exit"__ until __menuconfig__ quits

## Run the App

Finally we run the NuttX Firmware and start our app...

1.  Build ("make"), flash and run the NuttX Firmware on BL602 or ESP32.

1.  In the NuttX Shell, enter...

    ```bash
    spi_test
    ```

1.  We should see the output below.

    Congratulations we have created the __"spi_test"__ app!

    !["spi_test" running on BL602](https://lupyuen.github.io/images/spi2-newapp5.png)

# Appendix: Build, Flash and Run Nuttx

_(For BL602 and ESP32)_

TODO

Build, Flash and Run #NuttX OS on #BL602 ... Here's the script I use for macOS

![](https://lupyuen.github.io/images/spi2-script.png)

# Appendix: NuttX SPI Interface

_(For BL602 and ESP32)_

TODO

#NuttX SPI Interface is defined here ... Let's call it from our "spi_test" app

[(Source)](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/spi/spi.h)

![](https://lupyuen.github.io/images/spi2-interface.png)

TODO30

Can our #NuttX App directly call the SPI Interface? Let's find out! 🤔

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test/spi_test_main.c)

![](https://lupyuen.github.io/images/spi2-interface2.png)

TODO31

#NuttX SPI Interface needs an SPI Device "spi_dev_s" ... How do we get an SPI Device? 🤔

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L932-L967)

![](https://lupyuen.github.io/images/spi2-interface3.png)

TODO32

Tracing thru #NuttX Virtual File System ... We see that ioctl() maps the File Descriptor to a File Struct

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/fs/vfs/fs_ioctl.c#L118-L138)

![](https://lupyuen.github.io/images/spi2-interface4.png)

TODO33

#NuttX File Struct contains a Private Pointer to the SPI Driver "spi_driver_s"

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/drivers/spi/spi_driver.c#L112-L147)

![](https://lupyuen.github.io/images/spi2-interface5.png)

TODO34

#NuttX SPI Driver "spi_driver_s" contains the SPI Device "spi_dev_s" ... That we need for testing the SPI Interface! But the SPI Device is private and hidden from apps 🙁

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/drivers/spi/spi_driver.c#L55-L65)

![](https://lupyuen.github.io/images/spi2-interface6.png)

# Appendix: MISO And MOSI Are Swapped

_(For BL602 only)_

TODO

How to verify the #NuttX SPI Output? We sniff the #BL602 SPI Bus with a Logic Analyser

[(Source)](https://lupyuen.github.io/articles/spi#appendix-troubleshoot-bl602-spi-with-logic-analyser)

![](https://lupyuen.github.io/images/spi2-logic4.jpg)

TODO26

In #NuttX the SPI Pins for #BL602 are defined in "board.h" ... MOSI is GPIO 1, MISO is GPIO 0

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/risc-v/bl602/bl602evb/include/board.h#L87-L92)

![](https://lupyuen.github.io/images/spi2-driver5.png)

TODO27

#NuttX's SPI Pins match the #BL602 Reference Manual: MOSI = GPIO 1, MISO = GPIO 0 ... But we're about to witness a BL602 SPI Quirk

[(Source)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

![](https://lupyuen.github.io/images/spi2-driver6.png)

TODO37

Logic Analyser connected to #BL602 shows that MISO and MOSI are swapped! This happens in BL602 IoT SDK ... Also in #NuttX!

[(Source)](https://lupyuen.github.io/articles/spi#spi-data-pins-are-flipped)

![](https://lupyuen.github.io/images/spi2-logic.png)

TODO28

We can swap MISO and MOSI on #BL602 by setting a Hardware Register ... Let's do this on #NuttX

[(Source)](https://lupyuen.github.io/articles/pinedio#spi-pins-are-swapped)

Here's how we swap #BL602 MOSI and MISO on #NuttX ... So that the SPI Pins are consistent with the BL602 Reference Manual

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/swap_miso_mosi/arch/risc-v/src/bl602/bl602_spi.c#L1080-L1140)

![](https://lupyuen.github.io/images/spi2-driver7.png)

TODO38

After swapping #BL602 MISO and MOSI at #NuttX startup ... Logic Analyser shows that the SPI Pins are now consistent with BL602 Reference Manual! 🎉

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/swap_miso_mosi/arch/risc-v/src/bl602/bl602_spi.c#L1080-L1140)

![](https://lupyuen.github.io/images/spi2-logic2.png)

# Appendix: PineDio Stack BL604

TODO

![](https://lupyuen.github.io/images/spi2-pinedio2.jpg)

TODO8

![](https://lupyuen.github.io/images/spi2-pinedio3.jpg)

TODO9

![](https://lupyuen.github.io/images/spi2-pinedio8.jpg)

TODO10

![](https://lupyuen.github.io/images/spi2-pinedio9.jpg)

TODO11

![](https://lupyuen.github.io/images/spi2-pinedio7.jpg)

TODO12

![](https://lupyuen.github.io/images/spi2-pinedio5.jpg)

TODO14

![](https://lupyuen.github.io/images/spi2-pinedio6.jpg)

TODO16

![](https://lupyuen.github.io/images/spi2-pinedio4.jpg)

TODO18

![](https://lupyuen.github.io/images/spi2-pinedio10.jpg)
