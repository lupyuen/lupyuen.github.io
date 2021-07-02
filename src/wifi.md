# Reverse Engineering WiFi on RISC-V BL602

📝 _9 Jul 2021_

_What happens inside the WiFi Driver on RISC-V BL602 SoC... And how we found the (incomplete) source code for the driver_

Why reverse engineer the WiFi Driver?

TODO: Education, replacement, auditing, troubleshooting. [See this non-BL602 example](https://twitter.com/Yu_Wei_Wu/status/1406940637773979655?s=19)

![Quantitative Analysis of Decompiled BL602 WiFi Firmware](https://lupyuen.github.io/images/wifi-title.jpg)

# BL602 WiFi Demo Firmware

We start with the source code of the __BL602 WiFi Demo Firmware__ from the BL602 IoT SDK: [__`bl602_demo_wifi`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi)

TODO

From [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L769-L788)

```c
static void _cli_init()
{
    int codex_debug_cli_init(void);
    codex_debug_cli_init();
    easyflash_cli_init();
    network_netutils_iperf_cli_register();
    network_netutils_tcpserver_cli_register();
    network_netutils_tcpclinet_cli_register();
    network_netutils_netstat_cli_register();
    network_netutils_ping_cli_register();
    sntp_cli_init();
    bl_sys_time_cli_init();
    bl_sys_ota_cli_init();
    blfdt_cli_init();
    wifi_mgmr_cli_init();
    bl_wdt_cli_init();
    bl_gpio_cli_init();
    looprt_test_cli_init();
}
```

TODO

From [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L729-L747)

```c
static void cmd_stack_wifi(char *buf, int len, int argc, char **argv)
{
    /*wifi fw stack and thread stuff*/
    static uint8_t stack_wifi_init  = 0;


    if (1 == stack_wifi_init) {
        puts("Wi-Fi Stack Started already!!!\r\n");
        return;
    }
    stack_wifi_init = 1;

    printf("Start Wi-Fi fw @%lums\r\n", bl_timer_now_us()/1000);
    hal_wifi_start_firmware_task();
    /*Trigger to start Wi-Fi*/
    printf("Start Wi-Fi fw is Done @%lums\r\n", bl_timer_now_us()/1000);
    aos_post_event(EV_WIFI, CODE_WIFI_ON_INIT_DONE, 0);

}
```

TODO

From [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L366-L372)

```c
static void wifi_sta_connect(char *ssid, char *password)
{
    wifi_interface_t wifi_interface;

    wifi_interface = wifi_mgmr_sta_enable();
    wifi_mgmr_sta_connect(wifi_interface, ssid, password, NULL, NULL, 0, 0);
}
```

TODO

From [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L704-L727)

```c
static void cmd_httpc_test(char *buf, int len, int argc, char **argv)
{
    static httpc_connection_t settings;
    static httpc_state_t *req;

    if (req) {
        printf("[CLI] req is on-going...\r\n");
        return;
    }
    memset(&settings, 0, sizeof(settings));
    settings.use_proxy = 0;
    settings.result_fn = cb_httpc_result;
    settings.headers_done_fn = cb_httpc_headers_done_fn;

    httpc_get_file_dns(
            "nf.cr.dandanman.com",
            80,
            "/ddm/ContentResource/music/204.mp3",
            &settings,
            cb_altcp_recv_fn,
            &req,
            &req
   );
}
```

[User Manual (Chinese)](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/Iperf_User_Manual.pdf)

# Connect to WiFi Access Point

TODO

# WiFi Background Task

TODO

# Decompiled WiFi Demo Firmware

TODO

[`BraveHeartFLOSSDev`](https://github.com/BraveHeartFLOSSDev) did an excellent job decompiling into C (with Ghidra) the BL602 WiFi Demo Firmware...

-   [__BraveHeartFLOSSDev/bl602nutcracker1__](https://github.com/BraveHeartFLOSSDev/bl602nutcracker1)

[(We'll refer to this forked version)](https://github.com/lupyuen/bl602nutcracker1)

# CEVA RivieraWaves

TODO

# Upper Medium Access Control Layer

TODO

# Lower Medium Access Control Layer

TODO

# WiFi PHY Layer

TODO

# WiFi Supplicant

TODO

Rockchip RK3399

# Quantitative Analysis

TODO

-   [Google Sheets](https://docs.google.com/spreadsheets/d/1C_XmkH-ZSXz9-V2HsYBv7K1KRx3RF3-zsoJRLh1GwxI/edit?usp=sharing)

-   [LibreOffice / OpenOffice Format](https://github.com/lupyuen/bl602nutcracker1/blob/main/bl602_demo_wifi.ods)

-   [Excel Format](https://github.com/lupyuen/bl602nutcracker1/blob/main/bl602_demo_wifi.xlsx)

-   [CSV Format (without analysis)](https://github.com/lupyuen/bl602nutcracker1/blob/main/bl602_demo_wifi.csv)

# Other Components

TODO

BL602 HAL, BL602 Standard Driver, LWIP, MbedTLS, FreeRTOS, AliOS, AWS MQTT, AWS IoT

# GitHub Search Is Our Best Friend!

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
