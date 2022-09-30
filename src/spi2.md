# SPI on Apache NuttX OS

📝 _13 Dec 2021_

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

(Watch for the __"For ESP32"__ tags)

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

We begin by fetching the [__SPI Interface__](https://lupyuen.github.io/articles/spi2#appendix-nuttx-spi-interface) from the File Struct.

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

That's the __SPI Interface__ for NuttX.

[(More about NuttX SPI Interface)](https://lupyuen.github.io/articles/spi2#appendix-nuttx-spi-interface)

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

[(SPI_SETMODE, SPI_SETBITS, SPI_HWFEATURES and SPI_SETFREQUENCY are defined in the NuttX SPI Interface)](https://lupyuen.github.io/articles/spi2#appendix-nuttx-spi-interface)

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

[(More about the SPI Mode Quirk)](https://lupyuen.github.io/articles/spi2#appendix-spi-mode-quirk)

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

    [(__For PineDio Stack BL604:__ The SPI Test Driver is already preinstalled)](https://lupyuen.github.io/articles/pinedio2#appendix-bundled-features)

1.  Configure the build...

    ```bash
    cd nuttx

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For PineDio Stack BL604: Configure the build for BL604
    ./tools/configure.sh bl602evb:pinedio

    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Edit the Build Config
    make menuconfig 
    ```

1.  Enable the SPI Peripheral and SPI Character Driver in menuconfig...

    [__"Enable SPI"__](https://lupyuen.github.io/articles/spi2#enable-spi)

    ![Enable SPI](https://lupyuen.github.io/images/spi2-debug.jpg)

1.  Enable our SPI Test Driver...

    [__"Enable SPI"__](https://lupyuen.github.io/articles/spi2#enable-spi)

    ![Select SPI Test Driver](https://lupyuen.github.io/images/spi2-newdriver6.png)

1.  Enable SPI logging for easier troubleshooting...

    [__"Enable Logging"__](https://lupyuen.github.io/articles/spi2#enable-logging)

    ![Enable logging](https://lupyuen.github.io/images/spi2-driver4.png)

1.  Save the configuration and exit menuconfig

    [(Here's the .config for BL602)](https://gist.github.com/lupyuen/93b553fdfcfa0221ccd6276706e72caf)

1.  __For ESP32:__ Edit [__esp32_bringup.c__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c#L118-L426) to register our SPI Test Driver [(See this)](https://lupyuen.github.io/articles/spi2#register-device-driver)

1.  Build, flash and run the NuttX Firmware on BL602 or ESP32...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/spi2#appendix-build-flash-and-run-nuttx)

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

    ![Enable SPI Test App in menuconfig](https://lupyuen.github.io/images/spi2-newapp4.jpg)

1.  Save the configuration and exit menuconfig

    [(Here's the .config for BL602)](https://gist.github.com/lupyuen/93b553fdfcfa0221ccd6276706e72caf)

1.  Build, flash and run the NuttX Firmware on BL602 or ESP32...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/spi2#appendix-build-flash-and-run-nuttx)

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

[(Which pins can be used? See this)](https://lupyuen.github.io/articles/expander#pin-functions)

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

[(BL602 has a quirk that swaps MISO and MOSI, the fix is explained here)](https://lupyuen.github.io/articles/spi2#appendix-miso-and-mosi-are-swapped)

# Control Chip Select with GPIO

_(For BL602 and ESP32)_

If we zoom out the above display in the Logic Analyser, we see a problem with __SPI Chip Select on BL602__...

![Chip Select goes Low after every byte](https://lupyuen.github.io/images/spi2-logic3.png)

BL602 sets Chip Select to __High after EVERY byte__!

This will be a problem for __Semtech SX1262__ (LoRa Transceiver)...

It expects Chip Select to be __High after the entire multi-byte command__ has been transmitted! (Not after every byte)

[(ESP32 doesn't have this problem, according to @4ever_freedom)](https://twitter.com/4ever_freedom/status/1549235596115181569)

_Can we control SPI Chip Select ourselves?_

Yes, we may control Chip Select ourselves with the __GPIO Output__ function in NuttX.

This means we designate a __GPIO Output Pin__ that will be used for Chip Select.

And we call NuttX to flip the pin Low and High, before and after each SPI transfer.

_Is there another reason for controlling Chip Select with GPIO?_

On many BL602 / ESP32 boards, the SPI Bus (MISO, MOSI and SCK) is __shared by multiple SPI Devices__.

But each SPI Device has its own __Chip Select Pin__.

For such boards we'll have to control each Chip Select Pin with GPIO.

[(PineDio Stack BL604 shares its SPI Bus with SX1262 Transceiver, ST7789 Display and SPI Flash)](https://lupyuen.github.io/articles/pinedio2)

## GPIO Output as Chip Select

Let's look at the code in __SPI Test App #2__ that controls Chip Select with GPIO: [spi_test2_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L42-L74)

```c
/* Open GPIO Output for SPI Chip Select */

int cs = open("/dev/gpout1", O_RDWR);
assert(cs >= 0);  /* TODO: Handle error */
```

(Renamed to __/dev/gpio1__ as of Dec 2021)

This is new: We open the GPIO Output device __"/dev/gpout1"__ for the SPI Chip Select Pin.

Next we __open our SPI Test Driver__ as before...

```c
/* Open SPI Test Driver */

int fd = open("/dev/spitest0", O_RDWR);
assert(fd >= 0);
```

Then we set our __GPIO Output / Chip Select__ to Low by calling __ioctl()__...

```c
/* Set SPI Chip Select to Low */

int ret = ioctl(cs, GPIOC_WRITE, 0);
assert(ret >= 0);
```

Now that the SPI Device is active, we can __transmit and receive__ our SPI data...

```c
/* Transmit command to SX1262: Get Status */

static char get_status[] = { 0xc0, 0x00 };
int bytes_written = write(fd, get_status, sizeof(get_status));
assert(bytes_written == sizeof(get_status));

/* Read response from SX1262 */

static char rx_data[256];  /* Buffer for SPI response */
int bytes_read = read(fd, rx_data, sizeof(rx_data));
assert(bytes_read == sizeof(get_status));
```

(We'll explain __get_status__ in the next section)

Finally we set our __GPIO Output / Chip Select__ to High... 

```c
/* Set SPI Chip Select to High */

ret = ioctl(cs, GPIOC_WRITE, 1);
assert(ret >= 0);

/* Close SPI Test Driver and GPIO Output */

close(fd);
close(cs);
```

And close the SPI Test Driver and GPIO Output.

Let's watch SPI Test App #2 in action with Semtech SX1262.

[(More about GPIO Output)](https://lupyuen.github.io/articles/nuttx#gpio-demo)

![Control Chip Select with GPIO](https://lupyuen.github.io/images/spi2-sx5.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L42-L74)

# Test with Semtech SX1262

_(For BL602 and ESP32)_

[__Semtech SX1262__](https://www.semtech.com/products/wireless-rf/lora-core/sx1262) is a LoRa Transceiver (Radio Transmitter + Receiver) that's not yet supported by NuttX.

[(Though the older model SX1276 is supported by NuttX)](https://github.com/apache/incubator-nuttx/tree/master/drivers/wireless/lpwan/sx127x)

Today we shall send two short commands to SX1262 for testing...

-   __Get Status:__ We transmit this sequence of bytes to SX1262...

    ```text
    C0 00
    ```

    We expect the SPI Response to look like this...

    ```text
    A2 22
    ```

    (The response might get muddled, we'll learn why in a while)

-   __Read Register 0x08:__  We transmit this sequence of bytes to SX1262...

    ```text
    1D 00 08 00 00
    ```

    We expect the SPI Response to end with __`0x80`__ like this...

    ```text
    A2 A2 A2 A2 80
    ```

    [(Register `0x08` is expected to have value `0x80` at startup)](https://lupyuen.github.io/articles/lorawan#troubleshoot-lorawan)

We send the __"Get Status"__ command with this code: [spi_test2_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L59-L83)

```c
/* Transmit command to SX1262: Get Status */

static char get_status[] = { 0xc0, 0x00 };
int bytes_written = write(fd, get_status, sizeof(get_status));
assert(bytes_written == sizeof(get_status));

/* Read response from SX1262 */

static char rx_data[256];  /* Buffer for SPI response */
int bytes_read = read(fd, rx_data, sizeof(rx_data));
assert(bytes_read == sizeof(get_status));

/* Show the received status */

printf("\nSX1262 Status is %d\n", (rx_data[1] >> 4) & 0b111);  /* Bits 6:4 */
```

And the __"Read Register 0x08"__ command with this code: [spi_test2_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L94-L117)

```c
/* Transmit command to SX1262: Read Register 8 */

static char read_reg[] = { 0x1d, 0x00, 0x08, 0x00, 0x00 };
bytes_written = write(fd, read_reg, sizeof(read_reg));
assert(bytes_written == sizeof(read_reg));

/* Read response from SX1262 */

bytes_read = read(fd, rx_data, sizeof(rx_data));
assert(bytes_read == sizeof(read_reg));

/* Show the received register value */

printf("\nSX1262 Register 8 is 0x%02x\n", rx_data[4]);
```

[(See the complete program)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c)

![Transmit command to SX1262: Read Register 0x08](https://lupyuen.github.io/images/spi2-sx6.png)

## Connect SX1262

We connect SX1262 to BL602 / ESP32 as follows...

SX1262 | BL602 Pin | ESP32 Pin | Colour
:-------: | :---------: | :--------: | :-----
__MOSI__ | GPIO 1  | GPIO 13 | Yellow
__MISO__ | GPIO 0  | GPIO 12 | Light Green
__SCK__  | GPIO 3  | GPIO 14 | Blue
__CS__   | GPIO 11 | GPIO 15 / 16 | Dark Green
__BUSY__ | GPIO 14 | GPIO 18 / 17 |
__DIO1__ | GPIO 17 | GPIO 22 |
__VCC__  | 3V3     | 3V3 | Red
__GND__  | GND     | GND | Black

Here's SX1262 connected to PineCone BL602...

![SX1262 connected to PineCone BL602](https://lupyuen.github.io/images/spi2-title.jpg)

(Busy and DIO1 Pins are not connected, we'll need them for LoRa in the next artice)

_Why did we connect Chip Select to GPIO 11 / 15 / 16?_

Remember that we're controlling SPI Chip Select ourselves through __GPIO Output__, which is defined as follows...

__For BL602:__ GPIO Output Pin is defined as __GPIO 11__ in [board.h](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/risc-v/bl602/bl602evb/include/board.h#L48-L49)

```c
#define BOARD_GPIO_OUT1 \
  (GPIO_OUTPUT | GPIO_FLOAT | \
  GPIO_FUNC_SWGPIO | GPIO_PIN11)
```

[(More about this)](https://lupyuen.github.io/articles/nuttx#configure-pins)

__For ESP32:__ GPIO Output Pin depends on our ESP32 Board (and may be customised)...

ESP32-DevKitC defines __GPIO 15__ as the default GPIO Output Pin: [esp32_gpio.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_gpio.c#L43-L67)

```c
/* Output pins. GPIO15 is used as an example, any other outputs could be used. */
#define GPIO_OUT1    15

/* Input pins. GPIO18 is used as an example, any other inputs could be
 * used.
 */
#define GPIO_IN1     18

/* Interrupt pins.  GPIO22 is used as an example, any other inputs could be
 * used.
 */
#define GPIO_IRQPIN1  22
```

ESP32-WROVER-KIT uses __GPIO 16__ for GPIO Output: [esp32_gpio.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-wrover-kit/src/esp32_gpio.c#L43-L67)

```c
#define GPIO_OUT1    16
#define GPIO_IN1     17
#define GPIO_IRQPIN1 22
```

TTGO-LoRa-ESP32 uses __GPIO 15__ for GPIO Output: [esp32_gpio.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/ttgo_lora_esp32/src/esp32_gpio.c#L43-L67)

```c
#define GPIO_OUT1    15
#define GPIO_IN1     18
#define GPIO_IRQPIN1 22
```

## Test SX1262

Follow these steps to run our SPI Test App #2 on BL602 or ESP32...

1.  Assume that we have downloaded and configured our NuttX code...

    [__"Load the SPI Test Driver"__](https://lupyuen.github.io/articles/spi2#load-the-spi-test-driver)

1.  Edit the build configuration...

    ```bash
    make menuconfig
    ```

1.  Enable the GPIO Driver...

    [__"Enable GPIO Driver"__](https://lupyuen.github.io/articles/nuttx#enable-gpio-driver)

    ![Enable the GPIO Driver](https://lupyuen.github.io/images/nuttx-menu7a.png)

1.  Hit "Exit" until the Top Menu appears

    ("NuttX/x64_64 Configuration")

1.  Enable SPI Test App #2...

    Select __"Application Configuration"__ → __"Examples"__

    Check the box for __"spi_test2"__

1.  Save the configuration and exit menuconfig

    [(Here's the .config for BL602)](https://gist.github.com/lupyuen/93b553fdfcfa0221ccd6276706e72caf)

1.  Build, flash and run the NuttX Firmware on BL602 or ESP32...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/spi2#appendix-build-flash-and-run-nuttx)

1.  In the NuttX Shell, enter...

    ```text
    spi_test2
    ```

    (Pic below)

1.  We should see the output from the __"Get Status"__ command...

    ```text
    Get Status: received
      8a 8a
    SX1262 Status is 0
    ```

    (This output is not quite correct, we'll explain why in the next section)

1.  And the output from the __"Read Register 0x08"__ command...

    ```text
    Read Register 8: received
      a8 a8 a8 a8 80
    SX1262 Register 8 is 0x80
    ```

    The value of Register 0x08 is correct: __`0x80`__

    Yep our NuttX App is working OK with SX1262!

![SPI Test App #2 reads the SX1262 Register correctly](https://lupyuen.github.io/images/spi2-sx.png)

[(BL602 has a quirk: We must use SPI Mode 1 instead of Mode 0 or the register value will be garbled)](https://lupyuen.github.io/articles/spi2#appendix-spi-mode-quirk)

Let's run SPI Test App #2 on a new gagdet with onboard SX1262: PineDio Stack BL604.

![PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio2a.jpg)

# Test with PineDio Stack

_(For BL604 only)_

Pine64 has just sent me a prototype of [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) (version 2, pic above) with onboard SX1262 LoRa Transceiver, ST7789 Display, SPI Flash, GPS, Compass, Touch Panel, Heart Rate Sensor, Vibrator, ...

(Yep multiple devices on the same SPI Bus)

Let's test NuttX with PineDio Stack BL604 and its __onboard SX1262__! Here are the innards...

![Inside PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio1.jpg)

Before testing, remember to connect the __LoRa Antenna__... 

(So we don't fry the SX1262 Transceiver as we charge up the Power Amplifier)

![PineDio Stack BL604 with Antenna](https://lupyuen.github.io/images/spi2-pinedio10a.jpg)

## Pin Definitions

Based on this schematic for PineDio Stack BL604 (version 2)...

> ![SX1262 Interface on PineDio Stack](https://lupyuen.github.io/images/spi2-pinedio3.png)

We update the following __BL604 Pin Definitions__ in [board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L42-L95)

SX1262 | BL604 Pin | NuttX Pin
:-------: | :---------: | :---------
__MOSI__ | GPIO 13 | BOARD_SPI_MOSI
__MISO__ | GPIO 0  | BOARD_SPI_MISO
__SCK__  | GPIO 11 | BOARD_SPI_CLK
__CS__   | GPIO 15 | BOARD_GPIO_OUT1
__BUSY__ | GPIO 10 | BOARD_GPIO_IN1
__DIO1__ | GPIO 19 | BOARD_GPIO_INT1
__NRESET__ | GPIO 18 | Not assigned yet

```c
/* Busy Pin for PineDio SX1262 */

#define BOARD_GPIO_IN1    (GPIO_INPUT | GPIO_FLOAT | \
                            GPIO_FUNC_SWGPIO | GPIO_PIN10)

/* SPI Chip Select for PineDio SX1262 */

#define BOARD_GPIO_OUT1   (GPIO_OUTPUT | GPIO_PULLUP | \
                            GPIO_FUNC_SWGPIO | GPIO_PIN15)

/* GPIO Interrupt (DIO1) for PineDio SX1262 */

#define BOARD_GPIO_INT1   (GPIO_INPUT | GPIO_PULLUP | \
                            GPIO_FUNC_SWGPIO | GPIO_PIN19)

/* SPI Configuration: Chip Select is unused because we control via GPIO instead */

#define BOARD_SPI_CS   (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN8)  /* Unused */
#define BOARD_SPI_MOSI (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN13)
#define BOARD_SPI_MISO (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN0)
#define BOARD_SPI_CLK  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN11)
```

[(Which pins can be used? See this)](https://lupyuen.github.io/articles/expander#pin-functions)

(Remember that GPIO Output __BOARD_GPIO_OUT1__ becomes our Chip Select)

Today we won't use __BOARD_GPIO_IN1__ (Busy Pin) and __BOARD_GPIO_INT1__ (DIO1).

But eventually we'll use them when we port the __LoRaWAN Stack__ to PineDio Stack BL604!

## Run NuttX on PineDio Stack

Our final task for today: Run SPI Test App #2 on PineDio Stack BL604 (with onboard SX1262)...

1.  Assume that we have downloaded and configured our NuttX code...

    [__"Load the SPI Test Driver"__](https://lupyuen.github.io/articles/spi2#load-the-spi-test-driver)

    [__"Test SX1262"__](https://lupyuen.github.io/articles/spi2#test-sx1262)

1.  Edit the __Pin Definitions__ as shown above...

    [boards/risc-v/bl602/bl602evb/include/board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L42-L95) 

1.  Build, flash and run the NuttX Firmware...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/spi2#appendix-build-flash-and-run-nuttx)

1.  In the NuttX Shell, enter...

    ```text
    spi_test2
    ```

    (Pic below)

1.  We should see the output from the __"Get Status"__ command...

    ```text
    Get Status: received
      a2 22
    SX1262 Status is 2
    ```

    (This looks different from the BL602 output, we'll explain why in a while)

1.  And the output from the __"Read Register 0x08"__ command...

    ```text
    Read Register 8: received
      a2 a2 a2 a2 80
    SX1262 Register 8 is 0x80
    ```

    The value of Register 0x08 is correct: __`0x80`__

    Our SPI Test App #2 runs OK on PineDio Stack BL604 with onboard SX1262! 🎉

    [(The results are consistent with SX1262 tested on Linux with SPI Mode 0)](https://github.com/lupyuen/lora-sx1262#read-registers)

![NuttX on PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio2.png)

## Chip Select

_Why did the "Get Status" command return different results on BL602 vs BL604?_

On PineCone BL602 we configure __GPIO Output (Chip Select)__ like this...

```c
#define BOARD_GPIO_OUT1 \
  (GPIO_OUTPUT | GPIO_FLOAT | \
  GPIO_FUNC_SWGPIO | GPIO_PIN11)
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/risc-v/bl602/bl602evb/include/board.h#L48-L49)

On PineDio Stack BL604 we do this...

```c
#define BOARD_GPIO_OUT1 \
  (GPIO_OUTPUT | GPIO_PULLUP | \
  GPIO_FUNC_SWGPIO | GPIO_PIN15)
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L47-L50)

See the difference? PineCone BL602 configures the GPIO Output (Chip Select) as __GPIO_FLOAT__, whereas BL604 configures it as __GPIO_PULLUP__.

With __GPIO_FLOAT__, Chip Select defaults to the __Low State__ at startup.

Which __activates SX1262__ on the SPI Bus at startup, possibly interpreting spurious commands and causing the "Get Status" command to fail.

PineDio Stack BL604 does it correctly: It sets Chip Select to the __High State__ at startup (__GPIO_PULLUP__).  Which __deactivates SX1262__ on the SPI Bus at startup.

_Anything else we missed?_

On PineDio Stack BL604 the SPI Bus is __shared by multiple SPI Devices__: SX1262 Transceiver, ST7789 Display, SPI Flash.

We ought to flip the Chip Select for other SPI Devices to High, to deactivate the other devices and __prevent crosstalk__ on the SPI Bus.

# What's Next

Now that we have NuttX talking OK to the SX1262 LoRa Transceiver... We're ready to port __LoRa and LoRaWAN__ to NuttX!

Over the next couple of articles we shall __migrate the LoRa + LoRaWAN code incrementally__ to NuttX...

-   [__"LoRa SX1262 on Apache NuttX OS"__](https://lupyuen.github.io/articles/sx1262)

-   [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

NuttX works great with the __ST7789 SPI Display__ and LVGL Graphics Libary, right out of the box...

-   [__"ST7789 Display with LVGL Graphics on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/st7789)

We'll also explore __I2C on NuttX__, which is super useful for IoT sensors...

-   [__"Apache NuttX Driver for BME280 Sensor: Ported from Zephyr OS"__](https://lupyuen.github.io/articles/bme280)

I'm super excited about porting the [__Rust Embedded HAL__](https://lupyuen.github.io/articles/nuttx#rust-on-nuttx) to NuttX. Here's how we integrated NuttX GPIO, SPI and I2C with Rust...

-   [__"Rust on Apache NuttX OS"__](https://lupyuen.github.io/articles/rust2)

-   [__"Rust talks I2C on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rusti2c)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/rf3smq/spi_on_apache_nuttx_os/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/spi2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/spi2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1464898624026906625)

1.  We have already ported LoRaWAN to __BL602 IoT SDK__ [(see this)](https://lupyuen.github.io/articles/lorawan), why are we porting again to NuttX?

    Regrettably BL602 IoT SDK has been revamped (without warning) to the __new "hosal" HAL__ [(see this)](https://twitter.com/MisterTechBlog/status/1456259223323508748), and the LoRaWAN Stack will __no longer work__ on the revamped BL602 IoT SDK.

    For easier maintenance, we shall __code our BL602 and BL604 projects with Apache NuttX OS__ instead.

    (Which won't get revamped overnight!)

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

    ## Erase the Build Config
    make distclean

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For PineDio Stack BL604: Configure the build for BL604
    ./tools/configure.sh bl602evb:pinedio

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

    __For BL602:__ Check the box for __"BL602 Peripheral Support"__ → __"SPI0"__

    __For ESP32:__ Check the box for __"ESP32 Peripheral Select"__ → __"SPI 2"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

    ![Enable SPI](https://lupyuen.github.io/images/spi2-debug.jpg)

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

    __For LoRaWAN:__ Uncheck the following...

    ```text
    Enable Informational Debug Output
    GPIO Informational Output
    SPI Informational Output
    ```

1.  Hit __"Save"__ then __"OK"__ to save the NuttX Configuration to __".config"__

    [(Here's the .config for BL602)](https://gist.github.com/lupyuen/93b553fdfcfa0221ccd6276706e72caf)

1.  Hit __"Exit"__ until __menuconfig__ quits

    ![Enable logging](https://lupyuen.github.io/images/spi2-driver4.png)

## Register Device Driver

During NuttX startup, we need to register our Device Driver like so...

1.  Browse to the __Board Folder__...

    __For BL602:__ [__nuttx/nuttx/boards/ risc-v/bl602/bl602evb__](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src) 

    __For ESP32:__ [__nuttx/nuttx/boards/ xtensa/esp32/esp32-devkitc__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src)

    (Change "esp32-devkitc" to our ESP32 board)

1.  Edit the __Bringup Code__...

    __For BL602:__ [__bl602_bringup.c__](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L599-L617)

    __For ESP32:__ [__esp32_bringup.c__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c#L118-L426)

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

    __For ESP32:__ Edit the function [__esp32_bringup()__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c#L118-L426) and insert the code above. Change __"bl602_spibus_initialize(0)"__ to __"esp32_spibus_initialize(2)"__. [(Like this)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/common/src/esp32_board_spidev.c#L47-L72)

    [(Thanks @4ever_freedom!)](https://twitter.com/4ever_freedom/status/1546857560623517699)

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

    ![NuttX fails to start if we don't enable SPI](https://lupyuen.github.io/images/spi2-crash2.jpg)

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

    ![Copy the "hello" subfolder and paste it as "spi_test"](https://lupyuen.github.io/images/spi2-newapp.jpg)

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

    ## Erase the Build Config
    make distclean

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For PineDio Stack BL604: Configure the build for BL604
    ./tools/configure.sh bl602evb:pinedio
    
    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Restore the Build Config
    cp ../config .config

    ## Edit the Build Config
    make menuconfig 
    ```

    ![Select "spi_test" in menuconfig](https://lupyuen.github.io/images/spi2-newapp4.jpg)

## Enable App

Next we enable our app (pic above)...

1.  In __menuconfig__, select __"Application Configuration"__ → __"Examples"__

1.  Check the box for __"spi_test"__

1.  Hit __"Save"__ then __"OK"__ to save the NuttX Configuration to __".config"__

    [(Here's the .config for BL602)](https://gist.github.com/lupyuen/93b553fdfcfa0221ccd6276706e72caf)

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

# Appendix: Build, Flash and Run NuttX

_(For BL602 and ESP32)_

Below are the steps to build, flash and run NuttX on BL602 and ESP32.

The instructions below will work on __Linux (Ubuntu)__, __WSL (Ubuntu)__ and __macOS__.

[(Instructions for other platforms)](https://nuttx.apache.org/docs/latest/quickstart/install.html)

[(See this for Arch Linux)](https://popolon.org/gblog3/?p=1977&lang=en)

## Build NuttX

Follow these steps to build NuttX for BL602 or ESP32...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Assume that we have downloaded and configured our NuttX code...

    [__"Load the SPI Test Driver"__](https://lupyuen.github.io/articles/spi2#load-the-spi-test-driver)

1.  Build NuttX...

    ```bash
    make
    ```

1.  We should see...

    ```text
    LD: nuttx
    CP: nuttx.hex
    CP: nuttx.bin
    ```

    [(See the complete log for BL602)](https://gist.github.com/lupyuen/8f725c278c25e209c1654469a2855746)

1.  __For WSL:__ Copy the __NuttX Firmware__ to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    For WSL we need to run __blflash__ under plain old Windows CMD (not WSL) because it needs to access the COM port.

1.  In case of problems, refer to the __NuttX Docs__...

    [__"BL602 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html)

    [__"ESP32 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html)

    [__"Installing NuttX"__](https://nuttx.apache.org/docs/latest/quickstart/install.html)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

__For ESP32:__ [__See instructions here__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html#flashing) [(Also check out this article)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602:__ Follow these steps to install __blflash__...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File __nuttx.bin__ has been copied to the __blflash__ folder.

Set BL602 / BL604 to __Flashing Mode__ and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __High__ [(Like this)](https://lupyuen.github.io/images/pinedio-high.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash __nuttx.bin__ to BL602 / BL604 over UART...

```bash
## For Linux: Change "/dev/ttyUSB0" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/ttyUSB0 

## For macOS: Change "/dev/tty.usbserial-1410" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/tty.usbserial-1410 \
  --initial-baud-rate 230400 \
  --baud-rate 230400

## For Windows: Change "COM5" to the BL602 / BL604 Serial Port
blflash flash c:\blflash\nuttx.bin --port COM5
```

[(See the Output Log)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

For WSL: Do this under plain old Windows CMD (not WSL) because __blflash__ needs to access the COM port.

[(Flashing WiFi apps to BL602 / BL604? Remember to use __bl_rfbin__)](https://github.com/apache/incubator-nuttx/issues/4336)

[(More details on flashing firmware)](https://lupyuen.github.io/articles/flash#flash-the-firmware)

![Flashing NuttX](https://lupyuen.github.io/images/nuttx-flash2.png)

## Run NuttX

__For ESP32:__ Use Picocom to connect to ESP32 over UART...

```bash
picocom -b 115200 /dev/ttyUSB0
```

[(More about this)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602:__ Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __Low__ [(Like this)](https://lupyuen.github.io/images/pinedio-low.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602 / BL604's UART Port at 2 Mbps like so...

__For Linux:__

```bash
screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

Press Enter to reveal the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

Congratulations NuttX is now running on BL602 / BL604!

[(More details on connecting to BL602 / BL604)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

![Running NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

__macOS Tip:__ Here's the script I use to build, flash and run NuttX on macOS, all in a single step: [run.sh](https://gist.github.com/lupyuen/cc21385ecc66b5c02d15affd776a64af)

![Script to build, flash and run NuttX on macOS](https://lupyuen.github.io/images/spi2-script.png)

[(Source)](https://gist.github.com/lupyuen/cc21385ecc66b5c02d15affd776a64af)

# Appendix: NuttX SPI Interface

_(For BL602 and ESP32)_

In this section we dig deep into NuttX OS to understand how the __SPI Functions__ work.

![NuttX SPI Interface](https://lupyuen.github.io/images/spi2-interface.png)

[(Source)](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/spi/spi.h)

The __NuttX SPI Interface__ (pic above) is defined as C Macros in [include/nuttx/spi/spi.h](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/spi/spi.h)

-   __SPI_LOCK__: Lock the SPI Bus for exclusive access

-   __SPI_SELECT__: Enable / disable the SPI Chip Select

-   __SPI_SETFREQUENCY__: Set the SPI frequency

-   __SPI_SETDELAY__: Set the SPI Delays in nanoseconds

-   __SPI_SETMODE__: Set the SPI Mode

-   __SPI_SETBITS__: Set the number of bits per word (Transfer size)

-   __SPI_HWFEATURES__: Set hardware-specific feature flags

-   __SPI_STATUS__: Get SPI/MMC status

-   __SPI_CMDDATA__: Transfer 9-bit data (like for ST7789 Display)

-   __SPI_SEND__: Exchange one word on SPI

-   __SPI_SNDBLOCK__: Send a block of data on SPI

-   __SPI_RECVBLOCK__: Receive a block of data from SPI

-   __SPI_EXCHANGE__: Exchange a block of data from SPI

-   __SPI_REGISTERCALLBACK__: Register a callback for media status change

-   __SPI_TRIGGER__: Trigger a previously configured DMA transfer

[(More about NuttX SPI)](https://nuttx.apache.org/docs/latest/components/drivers/special/spi.html)

## SPI Device

The above SPI Interface is meant to be called by __NuttX Device Drivers__ like so: [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L168-L208)

```c
/* Write the buffer to the SPI device */

static ssize_t spi_test_driver_write(
  FAR struct file *filep,
  FAR const char *buffer,
  size_t buflen)
{
  /* Get the SPI interface */

  FAR struct inode *inode = filep->f_inode;
  FAR struct spi_test_driver_dev_s *priv = inode->i_private;

  /* Omitted: Lock, configure and select the SPI interface */

  /* Transfer data to SPI interface */

  SPI_EXCHANGE(priv->spi, buffer, recv_buffer, buflen);
```

__SPI_EXCHANGE__ is defined in the SPI Interface as...

```c
#define SPI_EXCHANGE(d,t,r,l) \
  ((d)->ops->exchange(d,t,r,l))
```

[(Source)](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/spi/spi.h#L372-L395)

Which maps to [__bl602_spi_exchange__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/risc-v/src/bl602/bl602_spi.c#L932-L967) for BL602...

```c
static void bl602_spi_exchange(
  struct spi_dev_s *dev,
  const void *txbuffer, 
  void *rxbuffer,
  size_t nwords) {
  ...
```

(Or [__esp32_spi_exchange__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/xtensa/src/esp32/esp32_spi.c#L1132-L1174) for ESP32)

Note that the SPI Interface requires an __SPI Device__ (spi_dev_s) to be passed in.

Which is available to NuttX Device Drivers.

_Can a NuttX App call the SPI Interface directly like this?_

![Can a NuttX App call the SPI Interface like this?](https://lupyuen.github.io/images/spi2-interface2.png)

Nope this won't work, because NuttX Apps __can't access the SPI Device__ (spi_dev_s).

Let's dig into NuttX OS and find out why.

![SPI Interface needs an SPI Device (spi_dev_s)](https://lupyuen.github.io/images/spi2-interface3.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L932-L967)

## File Descriptor

In a NuttX App we may open the SPI Port __"/dev/spi0"__ to get a __File Descriptor__...

```c
int fd = open("/dev/spi0", O_RDWR);
```

_How is the File Descriptor linked to the SPI Device (spi_dev_s)?_

Well we use the File Descriptor to execute __File Operations__: read(), write(), ioctl(), ...

Tracing through the NuttX __Virtual File System__, we see that ioctl() maps the File Descriptor to a __File Struct__...

![ioctl() maps a File Descriptor to a File Struct](https://lupyuen.github.io/images/spi2-interface4.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/fs/vfs/fs_ioctl.c#L118-L138)

## File Struct

The __File Struct__ contains a Private Pointer to the __SPI Driver__ (spi_driver_s)...

![File Struct contains a Private Pointer to the SPI Driver (spi_driver_s)](https://lupyuen.github.io/images/spi2-interface5.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/drivers/spi/spi_driver.c#L112-L147)

## SPI Driver

The __SPI Driver__ (spi_driver_s) contains the __SPI Device__ (spi_dev_s)... 

![SPI Driver (spi_driver_s) contains the SPI Device (spi_dev_s)](https://lupyuen.github.io/images/spi2-interface6.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/drivers/spi/spi_driver.c#L55-L65)

Which is what we need for calling the __SPI Interface__!

But sadly the SPI Device is __private to NuttX OS__ and we can't access it from the NuttX App.

That's why we wrote our own __SPI Test Driver__ (which runs inside NuttX OS) to get access to the SPI Device and call the SPI Interface.

(By calling the SPI Test Driver from our __SPI Test App__)

In summary, NuttX maps a __File Descriptor__ to __SPI Device__ as follows...

File Descriptor → File Struct → SPI Driver (spi_driver_s) → SPI Device (spi_dev_s)

# Appendix: MISO And MOSI Are Swapped

_(For BL602 only)_

BL602 has an SPI issue that affects both NuttX and BL602 IoT SDK: __MISO and MOSI pins are swapped__, contrary to the Pin Descriptions in the BL602 Reference Manual.

In this section we...

1.  Reproduce the issue on NuttX

1.  Propose a fix for NuttX

1.  Test the fix

The fix has been merged into NuttX...

-   [__"riscv/bl602: Swap SPI MISO and MOSI"__](https://github.com/apache/incubator-nuttx/pull/4984)

(Thank you NuttX Maintainers! 🙂 )

Note that the __SPI Mode needs to be 1__ (instead of 0) for the SPI interface to operate correctly...

-   [__"SPI Mode Quirk"__](https://lupyuen.github.io/articles/spi2#appendix-spi-mode-quirk)

## Reproduce the issue

The default SPI Pins for NuttX are defined in [board.h](https://github.com/apache/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h#L78-L83)

```c
/* SPI Configuration */

#define BOARD_SPI_CS   (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN2)
#define BOARD_SPI_MOSI (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN1)
#define BOARD_SPI_MISO (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN0)
#define BOARD_SPI_CLK  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN3)
```

This says that __MISO__ is GPIO 0, __MOSI__ is GPIO 1.

This is consistent with the __Pin Description Table__ from [__BL602 Reference Manual__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) (Version 1.2, 17 Dec 2020, page 26)

![Pin Description from BL602 Reference Manual](https://lupyuen.github.io/images/spi2-driver6.png)

We test the SPI Port with an __SPI Test Driver__: [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L168-L208)

```c
/* Write the buffer to the SPI device */

static ssize_t spi_test_driver_write(
  FAR struct file *filep,
  FAR const char *buffer,
  size_t buflen)
{
  ...
  /* Transmit buffer to SPI device and receive the response */

  SPI_EXCHANGE(priv->spi, buffer, recv_buffer, buflen);
  recv_buffer_len = buflen;
```

Which is called by an __SPI Test App__: [spi_test_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test/spi_test_main.c)

```c
int main(int argc, FAR char *argv[])
{
  /* Open SPI Test Driver */

  int fd = open("/dev/spitest0", O_RDWR);
  assert(fd >= 0);

  /* Write to SPI Test Driver */

  static char data[] = "Hello World";
  int bytes_written = write(fd, data, sizeof(data));
  assert(bytes_written == sizeof(data));
```

We connect a __Logic Analyser__ to PineCone BL602 and verify the SPI output...

Logic Analyser | BL602 Pin
:-------: | :---------:
__MOSI__ | GPIO 1
__MISO__ | GPIO 0
__SCK__  | GPIO 3
__CS__   | GPIO 2
__GND__  | GND

![Logic Analyser connected to PineCone BL602](https://lupyuen.github.io/images/spi2-logic4.jpg)

Logic Analyser shows that __MISO and MOSI are swapped__...

![Logic Analyser shows that MISO and MOSI are swapped](https://lupyuen.github.io/images/spi2-logic.png)

Let's examine the proposed fix for the issue.

## Fix the issue

The same issue happens in __BL602 IoT SDK__...

-   [__"SPI Data Pins Are Flipped"__](https://lupyuen.github.io/articles/spi#spi-data-pins-are-flipped)

On BL602 IoT SDK we fix this issue by calling [__GLB_Swap_SPI_0_MOSI_With_MISO()__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c#L1281-L1298) to swap the MISO and MOSI pins...

```c
/****************************************************************************//**
 * @brief  swap SPI0 MOSI with MISO
 *
 * @param  newState: ENABLE or DISABLE
 *
 * @return SUCCESS or ERROR
 *
*******************************************************************************/
BL_Err_Type GLB_Swap_SPI_0_MOSI_With_MISO(BL_Fun_Type newState)
{
    uint32_t tmpVal = 0;

    tmpVal=BL_RD_REG(GLB_BASE,GLB_PARM);
    tmpVal=BL_SET_REG_BITS_VAL(tmpVal,GLB_REG_SPI_0_SWAP,newState);
    BL_WR_REG(GLB_BASE,GLB_PARM,tmpVal);

    return SUCCESS;
}
```

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c#L1281-L1298)

This function swaps MISO and MOSI by setting the GLB Hardware Register __GLB_PARM__ at bit __GLB_REG_SPI_0_SWAP__.

For NuttX we propose to port this function as [__bl602_swap_spi_0_mosi_with_miso()__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/risc-v/src/bl602/bl602_spi.c#L1080-L1104) in [arch/risc-v/src/bl602/bl602_spi.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/risc-v/src/bl602/bl602_spi.c#L1080-L1104)

```c
/****************************************************************************
 * Name: bl602_swap_spi_0_mosi_with_miso
 *
 * Description:
 *   Swap SPI0 MOSI with MISO
 *
 * Input Parameters:
 *   swap      - Non-zero to swap MOSI and MISO
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

static void bl602_swap_spi_0_mosi_with_miso(uint8_t swap)
{
  if (swap)
    {
      modifyreg32(BL602_GLB_GLB_PARM, 0, GLB_PARM_REG_SPI_0_SWAP);
    }
  else
    {
      modifyreg32(BL602_GLB_GLB_PARM, GLB_PARM_REG_SPI_0_SWAP, 0);
    }
}
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/risc-v/src/bl602/bl602_spi.c#L1080-L1104)

The function above will be called by [__bl602_spi_init()__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/risc-v/src/bl602/bl602_spi.c#L1106-L1141) in [arch/risc-v/src/bl602/bl602_spi.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/risc-v/src/bl602/bl602_spi.c#L1106-L1141) to swap MISO and MOSI during startup...

```c
/****************************************************************************
 * Name: bl602_spi_init
 *
 * Description:
 *   Initialize bl602 SPI hardware interface
 *
 * Input Parameters:
 *   dev      - Device-specific state data
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

static void bl602_spi_init(struct spi_dev_s *dev)
{
  struct bl602_spi_priv_s *priv = (struct bl602_spi_priv_s *)dev;
  const struct bl602_spi_config_s *config = priv->config;

  /* Initialize the SPI semaphore that enforces mutually exclusive access */

  nxsem_init(&priv->exclsem, 0, 1);

  bl602_configgpio(BOARD_SPI_CS);
  bl602_configgpio(BOARD_SPI_MOSI);
  bl602_configgpio(BOARD_SPI_MISO);
  bl602_configgpio(BOARD_SPI_CLK);

  /* set master mode */

  bl602_set_spi_0_act_mode_sel(1);

  /* swap MOSI with MISO to be consistent with BL602 Reference Manual */

  bl602_swap_spi_0_mosi_with_miso(1);
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/risc-v/src/bl602/bl602_spi.c#L1106-L1141)

## Test the fix

After applying the fix, we see that the __MOSI output is now correct__...

![Logic Analyser after applying the fix](https://lupyuen.github.io/images/spi2-logic2.png)

As for __MISO input__, we tested with PineCone BL602 connected to __Semtech SX1262__.  We verified that the register data was read correctly over SPI...

-   [__"Test with Semtech SX1262"__](https://lupyuen.github.io/articles/spi2#test-with-semtech-sx1262)

We have also tested the fix with __PineDio Stack BL604__ and its onboard SX1262...

-   [__"Test with PineDio Stack"__](https://lupyuen.github.io/articles/spi2#test-with-pinedio-stack)

The fix has been merged into NuttX...

-   [__"riscv/bl602: Swap SPI MISO and MOSI"__](https://github.com/apache/incubator-nuttx/pull/4984)

(Thank you NuttX Maintainers! 🙂 )

Note that the __SPI Mode needs to be 1__ (instead of 0) for our test to succeed...

-   [__"SPI Mode Quirk"__](https://lupyuen.github.io/articles/spi2#appendix-spi-mode-quirk)

# Appendix: SPI Mode Quirk

_(For BL602 only)_

Due to an __SPI Mode Quirk__ in BL602, we configure BL602 to talk to Semtech SX1262 with __SPI Mode 1__ (instead of Mode 0).

(Which is quirky because SX1262 supports Mode 0, not Mode 1)

This is defined in [spi_test_driver.c](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L45-L57)

```c
/* For BL602 we use SPI Mode 1 instead of Mode 0 due to SPI quirk */

#ifdef CONFIG_BL602_SPI0
#define SPI_TEST_DRIVER_SPI_MODE (SPIDEV_MODE1) /* SPI Mode 1: Workaround for BL602 */
#else
#define SPI_TEST_DRIVER_SPI_MODE (SPIDEV_MODE0) /* SPI Mode 0: CPOL=0,CPHA=0 */
#endif /* CONFIG_BL602_SPI0 */
```

Let's watch what happens if we use __SPI Mode 0__ (instead of Mode 1) when BL602 talks to Semtech SX1262...

```c
#define SPI_TEST_DRIVER_SPI_MODE (SPIDEV_MODE0) /* SPI Mode 0: CPOL=0,CPHA=0 */
```

We run [spi_test2_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L94-L117) to __Read Register `0x08`__ from SX1262 over SPI...

```c
/* Transmit command to SX1262: Read Register 8 */

static char read_reg[] = { 0x1d, 0x00, 0x08, 0x00, 0x00 };
bytes_written = write(fd, read_reg, sizeof(read_reg));
assert(bytes_written == sizeof(read_reg));

/* Read response from SX1262 */

bytes_read = read(fd, rx_data, sizeof(rx_data));
assert(bytes_read == sizeof(read_reg));

/* Show the received register value */

printf("\nSX1262 Register 8 is 0x%02x\n", rx_data[4]);
```

We expect the value of Register `0x08` to be __0x80__.

With SPI Mode 0, the register value received over SPI is __incorrect__ (`0x5A`)...

```text
Read Register 8: received
  a8 a8 00 43 5a
SX1262 Register 8 is 0x5a
```

![SPI Mode 0: Register 8 is incorrect](https://lupyuen.github.io/images/spi2-sx2.png)

When we switch to SPI Mode 1, we get the correct value: __0x80__...

```text
Read Register 8: received
  a8 a8 a8 a8 80
SX1262 Register 8 is 0x80
```

![SPI Mode 1: Register 8 is correct](https://lupyuen.github.io/images/spi2-sx.png)

This SPI Mode Quirk has been observed on __BL602 IoT SDK__ when tested with...

-   [__BME280 Sensor__](https://lupyuen.github.io/articles/spi#spi-phase-looks-sus)

-   [__SX1262 LoRa Transceiver__](https://lupyuen.github.io/articles/lorawan#appendix-bl602-spi-functions)

-   [__SX1276 LoRa Transceiver__](https://lupyuen.github.io/articles/lora#spi)

-   [__ST7789 Display Controller__](https://lupyuen.github.io/articles/display#initialise-spi-port) (SPI Mode 3)

This is why we always use SPI Mode 1 instead of Mode 0 on BL602.

__UPDATE:__ BL602 talks to SPI Devices in SPI Mode 1 or Mode 3, depending on whether the MISO / MOSI Pins are swapped. [(See this)](https://lupyuen.github.io/articles/pinedio2#st7789-spi-mode)

![Using SPI Mode 1 instead of Mode 0 on BL602](https://lupyuen.github.io/images/spi2-sx7.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L51-L57)
