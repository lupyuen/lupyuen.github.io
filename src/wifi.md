# Reverse Engineering WiFi on RISC-V BL602

📝 _9 Jul 2021_

_What happens inside the WiFi Driver on RISC-V BL602 SoC... And how we found the (incomplete) source code for the driver_

Why reverse engineer the WiFi Driver?

TODO: Education, replacement, auditing, troubleshooting. [See this non-BL602 example](https://twitter.com/Yu_Wei_Wu/status/1406940637773979655?s=19)

![Quantitative Analysis of Decompiled BL602 WiFi Firmware](https://lupyuen.github.io/images/wifi-title.jpg)

# BL602 WiFi Demo Firmware

Let's study the source code of the __BL602 WiFi Demo Firmware__ from the BL602 IoT SDK: [__`bl602_demo_wifi`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi)

In the demo firmware we shall...

1.  Register the __WiFi Event Handler__ that will handle WiFi Events

1.  Start the __WiFi Firmware Task__ that will control the BL602 WiFi Firmware

1.  Start the __WiFi Manager Task__ that will manage WiFi Connections

1.  Connect to a __WiFi Access Point__

1.  Send a __HTTP Request__

## Register WiFi Event Handler

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

  //  Post a WiFi Event to start WiFi Manager Task
  aos_post_event(
    EV_WIFI,                 //  Event Type
    CODE_WIFI_ON_INIT_DONE,  //  Event Code
    0);                      //  Event Argument
}
```

(We'll cover `hal_wifi_start_firmware_task` later in this article)

After starting the task, we post the WiFi Event `CODE_WIFI_ON_INIT_DONE` to __start the WiFi Manager Task__.

Let's look inside the WiFi Event Handler...

## Start WiFi Manager Task

Here's how we handle __WiFi Events__: [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L374-L512)

```c
//  Callback Function for WiFi Events
static void event_cb_wifi_event(input_event_t *event, void *private_data) {

  //  Handle the WiFi Event
  switch (event->code) {

    //  Posted by cmd_stack_wifi to start Wi-Fi Manager Task
    case CODE_WIFI_ON_INIT_DONE:

      //  Start the WiFi Manager Task (FreeRTOS)
      wifi_mgmr_start_background(&conf);
      break;

    //  Omitted: Handle other WiFi Events
```

When we receive the WiFi Event `CODE_WIFI_ON_INIT_DONE`, we start the __WiFi Manager Task__ (in FreeRTOS) by calling `wifi_mgmr_start_background`.

`wifi_mgmr_start_background` comes from the BL602 WiFi Driver. [(See the source code)](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/wifi_mgmr.c#L1406-L1415)

## Connect to WiFi Network

Now that we have started both WiFi Background Tasks (WiFi Firmware Task and WiFi Manager Task), let's connect to a WiFi Network!

The demo firmware lets us enter this command to __connect to a WiFi Access Point__...

```text
# wifi_sta_connect YOUR_WIFI_SSID YOUR_WIFI_PASSWORD
```

Here's how the __`wifi_sta_connect`__ command is implemented: [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L366-L372)

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

We call [__`wifi_mgmr_sta_enable`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/wifi_mgmr_ext.c#L202-L217) from the BL602 WiFi Driver to __enable the WiFi Client__.

("STA" refers to "WiFi Station", which means WiFi Client)

Then we call [__`wifi_mgmr_sta_connect`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/wifi_mgmr_ext.c#L302-L307) (also from the BL602 WiFi Driver) to __connect to the WiFi Access Point__.

(We'll study the internals of `wifi_mgmr_sta_connect` in the next chapter)

## Send HTTP Request

Now we enter this command to __send a HTTP Request__ over WiFi...

```text
# httpc
```

Here's the implementation of the __`httpc`__ command: [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/bl602_demo_wifi/bl602_demo_wifi/main.c#L704-L727)

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

On BL602 we use [__LWIP, the Lightweight IP Stack__](https://www.nongnu.org/lwip/2_1_x/index.html) to do IP, UDP, TCP and HTTP Networking.

[`httpc_get_file_dns` is documented here](https://www.nongnu.org/lwip/2_1_x/group__httpc.html#gabd4ef2259885a93090733235cc0fa8d6)

For more details on the BL602 WiFi Demo Firmware, check out the docs...

-   [__BL602 WiFi Demo Firmware Docs__](https://pine64.github.io/bl602-docs/Examples/demo_wifi/wifi.html)

Let's reverse engineer the BL602 WiFi Demo Firmware... And learn what happens inside!

![Connecting to WiFi Access Point](https://lupyuen.github.io/images/wifi-connect.png)

# Connect to WiFi Access Point

_What really happens when BL602 connects to a WiFi Access Point?_

To understand how BL602 connects to a WiFi Access Point, let's read the __Source Code from the BL602 WiFi Driver__.

## Send request to WiFi Manager Task

Earlier we called __`wifi_mgmr_sta_connect`__ to connect to the WiFi Access Point.

Here's what happens inside: [`wifi_mgmr_ext.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/wifi_mgmr_ext.c#L302-L307)

```c
//  Connect to WiFi Access Point
int wifi_mgmr_sta_connect(wifi_interface_t *wifi_interface, char *ssid, char *psk, char *pmk, uint8_t *mac, uint8_t band, uint16_t freq) {
  //  Set WiFi SSID and PSK
  wifi_mgmr_sta_ssid_set(ssid);
  wifi_mgmr_sta_psk_set(psk);

  //  Connect to WiFi Access Point
  return wifi_mgmr_api_connect(ssid, psk, pmk, mac, band, freq);
}
```

We set the WiFi SSID and PSK. Then we call `wifi_mgmr_api_connect` to connect to the access point.

__`wifi_mgmr_api_connect`__ does this: [`wifi_mgmr_api.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/wifi_mgmr_api.c#L40-L84)

```c
//  Connect to WiFi Access Point
int wifi_mgmr_api_connect(char *ssid, char *psk, char *pmk, uint8_t *mac, uint8_t band, uint16_t freq) {
  //  Omitted: Copy PSK, PMK, MAC Address, Band and Frequency
  ...
  //  Send Connect Request to WiFi Manager Task
  wifi_mgmr_event_notify(msg);
  return 0;
}
```

![wifi_mgmr_api_connect](https://lupyuen.github.io/images/wifi-connect2.png)

Here we call `wifi_mgmr_event_notify` to __send the Connect Request__ to the WiFi Manager Task.

__`wifi_mgmr_event_notify`__ is defined in [`wifi_mgmr.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/wifi_mgmr.c#L1332-L1343) ...

```c
//  Send request to WiFi Manager Task
int wifi_mgmr_event_notify(wifi_mgmr_msg_t *msg) {
  //  Omitted: Wait for WiFi Manager to start
  ...
  //  Send request to WiFi Manager via Message Queue
  if (os_mq_send(
    &(wifiMgmr.mq),  //  Message Queue
    msg,             //  Request Message
    msg->len)) {     //  Message Length
    //  Failed to send request
    return -1;
  }
  return 0;
}
```

_How does `os_mq_send` send the request to the WiFi Manager Task?_

__`os_mq_send`__ calls FreeRTOS to deliver the Request Message to __WiFi Manager's Message Queue__: [`os_hal.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/os_hal.h#L174)

```c
#define os_mq_send(mq, msg, len) \
    (xMessageBufferSend(mq, msg, len, portMAX_DELAY) > 0 ? 0 : 1)
```

![wifi_mgmr_event_notify](https://lupyuen.github.io/images/wifi-connect3.png)

## WiFi Manager State Machine

The WiFi Manager runs a __State Machine__ in its Background Task (FreeRTOS) to manage the state of each WiFi Connection.

_What happens when WiFi Manager receives our request to connect to a WiFi Access Point?_

From [`wifi_mgmr.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/wifi_mgmr.c#L702-L745) ...

```c
static void stateIdleAction_connect( void *oldStateData, struct event *event,
      void *newStateData )
{
    wifi_mgmr_msg_t *msg;
    wifi_mgmr_profile_msg_t *profile_msg;

    msg = event->data;
    profile_msg = (wifi_mgmr_profile_msg_t*)msg->data;
    profile_msg->ssid_tail[0] = '\0';
    profile_msg->psk_tail[0] = '\0';
    os_printf(DEBUG_HEADER "Action Connect\r\n");
    os_printf("           ssid %s\r\n", profile_msg->ssid);
    os_printf("           ssid len %u\r\n", (unsigned int)profile_msg->ssid_len);
    os_printf("           psk %s\r\n", profile_msg->psk);
    os_printf("           psk len %u\r\n", (unsigned int)profile_msg->psk_len);
    os_printf("           pmk %s\r\n", profile_msg->pmk);
    os_printf("           pmk len %u\r\n", (unsigned int)profile_msg->pmk_len);
    os_printf("           channel band %d\r\n", (uint8_t)profile_msg->band);
    os_printf("           channel freq %d\r\n", (uint16_t)profile_msg->freq);
    os_printf("           mac %02X:%02X:%02X:%02X:%02X:%02X\r\n",
            profile_msg->mac[5],
            profile_msg->mac[4],
            profile_msg->mac[3],
            profile_msg->mac[2],
            profile_msg->mac[1],
            profile_msg->mac[0]
    );
    os_printf("           dhcp status: %s\r\n", profile_msg->dhcp_use ? "true" : "false");
    wifi_mgmr_profile_add(&wifiMgmr, profile_msg, -1);

    os_printf(DEBUG_HEADER "State Action ###%s### --->>> ###%s###\r\n",
            (char*)oldStateData,
            (char*)newStateData
    );

    //TODO Other security support
    bl_main_connect((const uint8_t *)profile_msg->ssid, profile_msg->ssid_len,
            (const uint8_t *)profile_msg->psk, profile_msg->psk_len,
            (const uint8_t *)profile_msg->pmk, profile_msg->pmk_len,
            (const uint8_t *)profile_msg->mac,
            (const uint8_t)profile_msg->band,
            (const uint16_t)profile_msg->freq
    );
}
```

TODO

![stateIdleAction_connect](https://lupyuen.github.io/images/wifi-connect4.png)

TODO

From [`bl_main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/bl_main.c#L189-L216)

```c
int bl_main_connect(const uint8_t* ssid, int ssid_len, const uint8_t *psk, int psk_len, const uint8_t *pmk, int pmk_len, const uint8_t *mac, const uint8_t band, const uint16_t freq)
{
    struct cfg80211_connect_params sme;

    memset(&sme, 0, sizeof(struct cfg80211_connect_params));
    sme.crypto.n_ciphers_pairwise = 0;
    sme.ssid_len = ssid_len;
    sme.ssid = ssid;
    sme.auth_type = NL80211_AUTHTYPE_AUTOMATIC;
    sme.key = psk;
    sme.key_len = psk_len;
    sme.pmk = pmk;
    sme.pmk_len = pmk_len;

    if (mac){
        sme.bssid = mac;
    }

    if (freq > 0) {
        sme.channel.center_freq = freq;
        sme.channel.band = band;
        sme.channel.flags = 0;
    }

    bl_cfg80211_connect(&wifi_hw, &sme);

    return 0;
}
```

TODO

From [`bl_main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/bl_main.c#L539-L571)

```c
int bl_cfg80211_connect(struct bl_hw *bl_hw, struct cfg80211_connect_params *sme)
{
    struct sm_connect_cfm sm_connect_cfm;
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    /* Forward the information to the LMAC */
    error = bl_send_sm_connect_req(bl_hw, sme, &sm_connect_cfm);
    if (error) {
        return error;
    }

    // Check the status
    switch (sm_connect_cfm.status)
    {
        case CO_OK:
            error = 0;
            break;
        case CO_BUSY:
            error = -EINPROGRESS;
            break;
        case CO_OP_IN_PROGRESS:
            error = -EALREADY;
            break;
        default:
            error = -EIO;
            break;
    }
    RWNX_DBG(RWNX_FN_LEAVE_STR);

    return error;
}
```

## Send request to LMAC

TODO

From [`bl_msg_tx.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/bl_msg_tx.c#L722-L804)

```c
int bl_send_sm_connect_req(struct bl_hw *bl_hw, struct cfg80211_connect_params *sme, struct sm_connect_cfm *cfm)
{
    struct sm_connect_req *req;
    int i;
    u32_l flags = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    /* Build the SM_CONNECT_REQ message */
    req = bl_msg_zalloc(SM_CONNECT_REQ, TASK_SM, DRV_TASK_ID,
                                   sizeof(struct sm_connect_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the SM_CONNECT_REQ message */
    if (sme->crypto.n_ciphers_pairwise &&
        ((sme->crypto.ciphers_pairwise[0] == WLAN_CIPHER_SUITE_WEP40) ||
         (sme->crypto.ciphers_pairwise[0] == WLAN_CIPHER_SUITE_TKIP) ||
         (sme->crypto.ciphers_pairwise[0] == WLAN_CIPHER_SUITE_WEP104)))
        flags |= DISABLE_HT;

    if (sme->crypto.control_port)
        flags |= CONTROL_PORT_HOST;

    if (sme->crypto.control_port_no_encrypt)
        flags |= CONTROL_PORT_NO_ENC;

    if (use_pairwise_key(&sme->crypto))
        flags |= WPA_WPA2_IN_USE;

    if (sme->mfp == NL80211_MFP_REQUIRED)
        flags |= MFP_IN_USE;

    if (sme->crypto.control_port_ethertype)
        req->ctrl_port_ethertype = sme->crypto.control_port_ethertype;
    else
        req->ctrl_port_ethertype = ETH_P_PAE;

    if (sme->bssid && !MAC_ADDR_CMP(sme->bssid, mac_addr_bcst.array) && !MAC_ADDR_CMP(sme->bssid, mac_addr_zero.array)) {
        for (i=0;i<ETH_ALEN;i++)
            req->bssid.array[i] = sme->bssid[i];
    }
    else
        req->bssid = mac_addr_bcst;
    req->vif_idx = bl_hw->vif_index_sta;
    if (sme->channel.center_freq) {
        req->chan.band = sme->channel.band;
        req->chan.freq = sme->channel.center_freq;
        req->chan.flags = passive_scan_flag(sme->channel.flags);
    } else {
        req->chan.freq = (u16_l)-1;
    }
    for (i = 0; i < sme->ssid_len; i++)
        req->ssid.array[i] = sme->ssid[i];
    req->ssid.length = sme->ssid_len;
    req->flags = flags;
    if (WARN_ON(sme->ie_len > sizeof(req->ie_buf)))
        return -EINVAL;
    if (sme->ie_len)
        memcpy(req->ie_buf, sme->ie, sme->ie_len);
    req->ie_len = sme->ie_len;
    req->listen_interval = bl_mod_params.listen_itv;
    req->dont_wait_bcmc = !bl_mod_params.listen_bcmc;

    /* Set auth_type */
    if (sme->auth_type == NL80211_AUTHTYPE_AUTOMATIC)
        req->auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
    else
        req->auth_type = sme->auth_type;

    /* Set UAPSD queues */
    req->uapsd_queues = bl_mod_params.uapsd_queues;
    req->is_supplicant_enabled = 1;
    if (sme->key_len) {
        memcpy(req->phrase, sme->key, sme->key_len);
    }
    if (sme->pmk_len) {
        memcpy(req->phrase_pmk, sme->pmk, sme->pmk_len);
    }

    /* Send the SM_CONNECT_REQ message to LMAC FW */
    return bl_send_msg(bl_hw, req, 1, SM_CONNECT_CFM, cfm);
}
```

TODO

![bl_send_sm_connect_req](https://lupyuen.github.io/images/wifi-connect5.png)

TODO

From [`bl_msg_tx.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/bl_msg_tx.c#L315-L371)

```c
static int bl_send_msg(struct bl_hw *bl_hw, const void *msg_params,
                         int reqcfm, lmac_msg_id_t reqid, void *cfm)
{
    struct lmac_msg *msg;
    struct bl_cmd *cmd;
    bool nonblock;
    int ret;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    msg = container_of((void *)msg_params, struct lmac_msg, param);

    if (!test_bit(RWNX_DEV_STARTED, &bl_hw->drv_flags) &&
        reqid != MM_RESET_CFM && reqid != MM_VERSION_CFM &&
        reqid != MM_START_CFM && reqid != MM_SET_IDLE_CFM &&
        reqid != ME_CONFIG_CFM && reqid != MM_SET_PS_MODE_CFM &&
        reqid != ME_CHAN_CONFIG_CFM) {
        os_printf("%s: bypassing (RWNX_DEV_RESTARTING set) 0x%02x\n", __func__, reqid);
        os_free(msg);
        RWNX_DBG(RWNX_FN_LEAVE_STR);
        return -EBUSY;
    } else if (!bl_hw->ipc_env) {
        os_printf("%s: bypassing (restart must have failed)\r\n", __func__);
        os_free(msg);
        RWNX_DBG(RWNX_FN_LEAVE_STR);
        return -EBUSY;
    }

    nonblock = is_non_blocking_msg(msg->id);

    cmd = os_malloc(sizeof(struct bl_cmd));
    if (NULL == cmd) {
        os_free(msg);
        os_printf("%s: failed to allocate mem for cmd, size is %d\r\n", __func__, sizeof(struct bl_cmd));
        return -ENOMEM;
    }
    memset(cmd, 0, sizeof(struct bl_cmd));
    cmd->result  = EINTR;
    cmd->id      = msg->id;
    cmd->reqid   = reqid;
    cmd->a2e_msg = msg;
    cmd->e2a_msg = cfm;
    if (nonblock)
        cmd->flags = RWNX_CMD_FLAG_NONBLOCK;
    if (reqcfm)
        cmd->flags |= RWNX_CMD_FLAG_REQ_CFM;
    ret = bl_hw->cmd_mgr.queue(&bl_hw->cmd_mgr, cmd);

    if (!nonblock) {
        os_free(cmd);
    } else {
        ret = cmd->result;
    }

    RWNX_DBG(RWNX_FN_LEAVE_STR);
    return ret;
}
```

![bl_send_msg](https://lupyuen.github.io/images/wifi-connect6.png)

TODO

From [`ipc_host.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/ipc_host.c#L139-L171)

```c
int ipc_host_msg_push(struct ipc_host_env_tag *env, void *msg_buf, uint16_t len)
{
    int i;
    uint32_t *src, *dst;

    REG_SW_SET_PROFILING(env->pthis, SW_PROF_IPC_MSGPUSH);

    ASSERT_ERR(!env->msga2e_hostid);
    ASSERT_ERR(round_up(len, 4) <= sizeof(env->shared->msg_a2e_buf.msg));

    // Copy the message into the IPC MSG buffer
#if 1
    src = (uint32_t*)((struct bl_cmd *)msg_buf)->a2e_msg;
#else
    src = (uint32_t*) msg_buf;
#endif
    dst = (uint32_t*)&(env->shared->msg_a2e_buf.msg);

    // Copy the message in the IPC queue
    for (i=0; i<len; i+=4)
    {
        *dst++ = *src++;
    }

    env->msga2e_hostid = msg_buf;

    // Trigger the irq to send the message to EMB
    ipc_app2emb_trigger_set(IPC_IRQ_A2E_MSG);

    REG_SW_CLEAR_PROFILING(env->pthis, SW_PROF_IPC_MSGPUSH);

    return 0;
}
```

TODO

![ipc_host_msg_push](https://lupyuen.github.io/images/wifi-connect9.png)

## Trigger LMAC Interrupt

TODO9

From [`reg_ipc_app.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_wifidrv/bl60x_wifi_driver/reg_ipc_app.h#L41-L69)

```c
#define REG_WIFI_REG_BASE         0x44000000
#define REG_IPC_APP_DECODING_MASK 0x0000007F

/**
 * @brief APP2EMB_TRIGGER register definition
 * <pre>
 *   Bits           Field Name   Reset Value
 *  -----   ------------------   -----------
 *  31:00      APP2EMB_TRIGGER   0x0
 * </pre>
 */
#define IPC_APP2EMB_TRIGGER_ADDR   0x12000000
#define IPC_APP2EMB_TRIGGER_OFFSET 0x00000000
#define IPC_APP2EMB_TRIGGER_INDEX  0x00000000
#define IPC_APP2EMB_TRIGGER_RESET  0x00000000

#ifndef __INLINE
#define __INLINE inline
#endif

static __INLINE u32 ipc_app2emb_trigger_get()
{
    return REG_IPC_APP_RD(REG_WIFI_REG_BASE, IPC_APP2EMB_TRIGGER_INDEX);
}

static __INLINE void ipc_app2emb_trigger_set(u32 value)
{
    REG_IPC_APP_WR(REG_WIFI_REG_BASE, IPC_APP2EMB_TRIGGER_INDEX, value);
}
```

TODO

![ipc_app2emb_trigger_set](https://lupyuen.github.io/images/wifi-connect8.png)

TODO8

![](https://lupyuen.github.io/images/wifi-connect7.png)

TODO7


# Decompiled WiFi Demo Firmware

_Are we really Reverse Engineering the BL602 WiFi Driver?_

Not quite. So far we've been reading the published source code for the BL602 WiFi Driver.

TODO

[`BraveHeartFLOSSDev`](https://github.com/BraveHeartFLOSSDev) did an excellent job decompiling into C (with Ghidra) the BL602 WiFi Demo Firmware...

-   [__BraveHeartFLOSSDev/bl602nutcracker1__](https://github.com/BraveHeartFLOSSDev/bl602nutcracker1)

[(We'll use this fork)](https://github.com/lupyuen/bl602nutcracker1)

## Linking to decompiled code

TODO

![](https://lupyuen.github.io/images/wifi-assert.png)

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

# CEVA RivieraWaves

TODO

-   [__mclown/AliOS-Things__](https://github.com/mclown/AliOS-Things/tree/master/platform/mcu/bk7231u/beken/ip)

[(We'll use this fork)](https://github.com/lupyuen/AliOS-Things/tree/master/platform/mcu/bk7231u/beken/ip)

![](https://lupyuen.github.io/images/wifi-rivierawaves.png)

TODO

![](https://lupyuen.github.io/images/wifi-ceva.png)

[(Source)](https://csimarket.com/stocks/markets_glance.php?code=CEVA#:~:text=Included%20among%20our%20licensees%20are,%2C%20RDA%2C%20Renesas%2C%20Rockchip%2C)

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

[(Source)](http://www.bekencorp.com/en/goods/detail/cid/13.html)

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

According to [__madushan1000 on Twitter__](https://twitter.com/madushan1000/status/1409392882612637696)...

-   [__fengmaoqiao/my_logic_code__](https://github.com/fengmaoqiao/my_logic_code)

-   [__fengmaoqiao/workplace__](https://github.com/fengmaoqiao/workplace)

# WiFi Supplicant

TODO: Rockchip RK3399

-   [__karthirockz/rk3399-kernel__](https://github.com/karthirockz/rk3399-kernel/tree/main/drivers/net/wireless/rockchip_wlan/mvl88w8977/mlan/esa)

[(We'll use this fork)](https://github.com/lupyuen/rk3399-kernel/tree/main/drivers/net/wireless/rockchip_wlan/mvl88w8977/mlan/esa)

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
