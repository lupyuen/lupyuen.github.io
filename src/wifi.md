# Reverse Engineering WiFi on RISC-V BL602

📝 _9 Jul 2021_

_What happens inside the WiFi Driver on RISC-V BL602 SoC... And how we found the (incomplete) source code for the driver_

Why reverse engineer the WiFi Driver?

TODO: Education, replacement, auditing, troubleshooting. [See this non-BL602 example](https://twitter.com/Yu_Wei_Wu/status/1406940637773979655?s=19)

![Quantitative Analysis of Decompiled BL602 WiFi Firmware](https://lupyuen.github.io/images/wifi-title.jpg)

# BL602 WiFi Demo Firmware

Let's study the source code of the __BL602 WiFi Demo Firmware__ from the BL602 IoT SDK: [__`bl602_demo_wifi`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi)

## Startup

When the firmware starts, we register a __Callback Function that will handle WiFi Events__: [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L819-L866)

```c
//  Called at startup to init drivers and run event loop
static void aos_loop_proc(void *pvParameters) {
  //  Omitted: Init the drivers
  ...
  //  Register Callback Function for WiFi Events
  aos_register_event_filter(
    EV_WIFI,              //  Event Type
    event_cb_wifi_event,  //  Event Callback Function
    NULL);                //  Event Callback Argument

  //  Start WiFi Networking Stack
  cmd_stack_wifi(NULL, 0, 0, NULL);

  //  Run event loop
  aos_loop_run();
}
```

(We'll see `event_cb_wifi_event` in a while)

This startup code calls __`cmd_stack_wifi`__ to start the WiFi Networking Stack.

Let's look inside...

## Start WiFi Firmware Task

In __`cmd_stack_wifi`__ we start the __WiFi Firmware Task__ like so: [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L729-L747)

```c
//  Start WiFi Networking Stack
static void cmd_stack_wifi(char *buf, int len, int argc, char **argv) {
  //  Check whether WiFi Networking is already started
  static uint8_t stack_wifi_init  = 0;
  if (1 == stack_wifi_init) { return; }  //  Already started
  stack_wifi_init = 1;

  //  Start WiFi Firmware Task (FreeRTOS)
  hal_wifi_start_firmware_task();

  //  Post a WiFi Event to start WiFi Networking
  aos_post_event(
    EV_WIFI,                 //  Event Type
    CODE_WIFI_ON_INIT_DONE,  //  Event Code
    0);                      //  Event Argument
}
```

(We'll cover `hal_wifi_start_firmware_task` in the next chapter)

After starting the task, we post the WiFi Event `CODE_WIFI_ON_INIT_DONE` to __start WiFi Networking__.

Let's look inside the WiFi Event Handler...

## Start WiFi Manager Task

Here's how we handle WiFi Events: [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L374-L512)

```c
//  Callback Function for WiFi Events
static void event_cb_wifi_event(input_event_t *event, void *private_data) {

  //  Handle the WiFi Event
  switch (event->code) {

    //  Posted by cmd_stack_wifi to start Wi-Fi Networking
    case CODE_WIFI_ON_INIT_DONE:

      //  Start the WiFi Manager Task (FreeRTOS)
      wifi_mgmr_start_background(&conf);
      break;

    //  Omitted: Handle other WiFi Events
```

When we receive the WiFi Event `CODE_WIFI_ON_INIT_DONE`, we start the __WiFi Manager Task__ by calling `wifi_mgmr_start_background`.

`wifi_mgmr_start_background` comes from the BL602 WiFi Driver.

TODO

## Connect to WiFi Access Point

TODO

```text
# wifi_sta_connect YOUR_WIFI_SSID YOUR_WIFI_PASSWORD
```

TODO

From [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L366-L372)

```c
//  Connect to WiFi Access Point
static void wifi_sta_connect(char *ssid, char *password) {

  //  Enable WiFi Client
  wifi_interface_t wifi_interface
    = wifi_mgmr_sta_enable();

  //  Connect to WiFi Access Point
  wifi_mgmr_sta_connect(
    wifi_interface,  //  WiFi Interface
    ssid,            //  SSID
    password,        //  Password
    NULL,            //  PMK
    NULL,            //  MAC Address
    0,               //  Band
    0);              //  Frequency
}
```

## Send HTTP Request

TODO

From [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L704-L727)

```c
//  Send a HTTP GET Request with LWIP
static void cmd_httpc_test(char *buf, int len, int argc, char **argv) {
  //  Check whether a HTTP Request is already running
  static httpc_connection_t settings;
  static httpc_state_t *req;
  if (req) { return; }  //  Request already running

  //  Init the LWIP HTTP Settings
  memset(&settings, 0, sizeof(settings));
  settings.use_proxy = 0;
  settings.result_fn = cb_httpc_result;
  settings.headers_done_fn = cb_httpc_headers_done_fn;

  //  Send a HTTP GET Request with LWIP
  httpc_get_file_dns(
    "nf.cr.dandanman.com",  //  Host
    80,                     //  Port
    "/ddm/ContentResource/music/204.mp3",  //  URI
    &settings,              //  Settings
    cb_altcp_recv_fn,       //  Callback Function
    &req,                   //  Callback Argument
    &req);                  //  Request
}
```

[Demo Firmware Documentation](https://pine64.github.io/bl602-docs/Examples/demo_wifi/wifi.html)

![](https://lupyuen.github.io/images/wifi-connect.png)

# Connect to WiFi Access Point

TODO

![](https://lupyuen.github.io/images/wifi-connect2.png)

TODO

![](https://lupyuen.github.io/images/wifi-connect3.png)

TODO

![](https://lupyuen.github.io/images/wifi-connect4.png)

TODO

![](https://lupyuen.github.io/images/wifi-connect5.png)

TODO

![](https://lupyuen.github.io/images/wifi-connect6.png)

TODO

![](https://lupyuen.github.io/images/wifi-connect7.png)

TODO

![](https://lupyuen.github.io/images/wifi-connect8.png)

TODO

![](https://lupyuen.github.io/images/wifi-connect9.png)

TODO

# WiFi Firmware Task

TODO

![](https://lupyuen.github.io/images/wifi-task.png)

TODO

![](https://lupyuen.github.io/images/wifi-task2.png)

TODO

![](https://lupyuen.github.io/images/wifi-task3.png)

TODO

![](https://lupyuen.github.io/images/wifi-task4.png)

TODO

![](https://lupyuen.github.io/images/wifi-task5.png)

TODO

![](https://lupyuen.github.io/images/wifi-task6.png)

TODO

# Decompiled WiFi Demo Firmware

TODO

[`BraveHeartFLOSSDev`](https://github.com/BraveHeartFLOSSDev) did an excellent job decompiling into C (with Ghidra) the BL602 WiFi Demo Firmware...

-   [__BraveHeartFLOSSDev/bl602nutcracker1__](https://github.com/BraveHeartFLOSSDev/bl602nutcracker1)

[(We'll use this fork)](https://github.com/lupyuen/bl602nutcracker1)

TODO

![](https://lupyuen.github.io/images/wifi-assert.png)

TODO

# CEVA RivieraWaves

TODO

-   [__mclown/AliOS-Things__](https://github.com/mclown/AliOS-Things)

[(We'll use this fork)](https://github.com/lupyuen/AliOS-Things)

![](https://lupyuen.github.io/images/wifi-rivierawaves.png)

TODO

![](https://lupyuen.github.io/images/wifi-ceva.png)

TODO

# Upper Medium Access Control Layer

TODO

# Lower Medium Access Control Layer

TODO

![](https://lupyuen.github.io/images/wifi-lmac.jpg)

TODO

![](https://lupyuen.github.io/images/wifi-lmac2.jpg)

TODO

![](https://lupyuen.github.io/images/wifi-lmac3.jpg)

TODO

![](https://lupyuen.github.io/images/wifi-beken.jpg)

TODO

![](https://lupyuen.github.io/images/wifi-beken2.png)

TODO

# WiFi PHY Layer

TODO

-   [__jixinintelligence/bl602-604__](https://github.com/jixinintelligence/bl602-604)

[(We'll use this fork)](https://github.com/lupyuen/bl602-604)

![](https://lupyuen.github.io/images/wifi-phy.png)

TODO

## WiFi RTL

TODO

-   [__fengmaoqiao/my_logic_code__](https://github.com/fengmaoqiao/my_logic_code)

-   [__fengmaoqiao/workplace__](https://github.com/fengmaoqiao/workplace)

# WiFi Supplicant

TODO: Rockchip RK3399

-   [__karthirockz/rk3399-kernel__](https://github.com/karthirockz/rk3399-kernel)

[(We'll use this fork)](https://github.com/lupyuen/rk3399-kernel)

![](https://lupyuen.github.io/images/wifi-rockchip.jpg)

TODO

![](https://lupyuen.github.io/images/wifi-supplicant.png)

TODO

![](https://lupyuen.github.io/images/wifi-supplicant2.png)

TODO

# Quantitative Analysis

TODO

-   [Google Sheets](https://docs.google.com/spreadsheets/d/1C_XmkH-ZSXz9-V2HsYBv7K1KRx3RF3-zsoJRLh1GwxI/edit?usp=sharing)

-   [LibreOffice / OpenOffice Format](https://github.com/lupyuen/bl602nutcracker1/blob/main/bl602_demo_wifi.ods)

-   [Excel Format](https://github.com/lupyuen/bl602nutcracker1/blob/main/bl602_demo_wifi.xlsx)

-   [CSV Format (without analysis)](https://github.com/lupyuen/bl602nutcracker1/blob/main/bl602_demo_wifi.csv)

![](https://lupyuen.github.io/images/wifi-quantify.png)

TODO

![](https://lupyuen.github.io/images/wifi-quantify2.png)

TODO

![](https://lupyuen.github.io/images/wifi-quantify3.png)

TODO

![](https://lupyuen.github.io/images/wifi-quantify4.png)

TODO

![Quantitative Analysis of Decompiled BL602 WiFi Firmware](https://lupyuen.github.io/images/wifi-title.jpg)

# Other Components

TODO: BL602 HAL, BL602 Standard Driver, LWIP, MbedTLS, FreeRTOS, AliOS, AWS MQTT, AWS IoT

# GitHub Search Is Our Best Friend!

TODO

![](https://lupyuen.github.io/images/wifi-schedule.png)

TODO

![](https://lupyuen.github.io/images/wifi-schedule2.png)

TODO

![](https://lupyuen.github.io/images/wifi-schedule3.png)

TODO

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/wifi.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/wifi.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1407971263088193540)
