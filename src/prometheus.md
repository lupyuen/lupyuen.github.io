# Monitor IoT Devices in The Things Network with Prometheus and Grafana

📝 _27 Oct 2021_

Suppose we have some __IoT Devices__ that transmit __Sensor Data__ (via LoRa and LoRaWAN) to __The Things Network__...

[(That's the free-to-use public global wireless network for IoT Devices)](https://lupyuen.github.io/articles/ttn)

> ![IoT Devices transmitting Sensor Data to The Things Network](https://lupyuen.github.io/images/grafana-flow3.jpg)

_How shall we monitor the Sensor Data transmitted by the IoT Devices?_

Today we shall monitor IoT Sensor Data by connecting open source __Prometheus and Grafana__ to The Things Network...

![Monitoring IoT Devices in The Things Network with Prometheus and Grafana](https://lupyuen.github.io/images/prometheus-title.jpg)

1.  __The Things Network__ pushes our __Sensor Data over MQTT__ in real time

1.  Our __MQTT Gateway__ consumes the Sensor Data...

1.  And publishes the Sensor Data to our __Prometheus Time Series Database__...

1.  Which gets rendered as a __Grafana Dashboard__ like this...

![Monitoring Devices on The Things Network with Prometheus and Grafana](https://lupyuen.github.io/images/prometheus-grafana4.png)

_Why Prometheus and Grafana?_

Prometheus works great for __storing and querying__ IoT Sensor Data.

And Grafana works well with Prometheus for __visualising IoT Sensor Data__.

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

In a while we shall demo this Prometheus + Grafana Setup with __PineDio Stack BL604 RISC-V Board__ (pic above)

-   [__"The Things Network on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/ttn)

But it should work for __any LoRaWAN Device__ connected to The Things Network... Assuming that we have configured a suitable __Payload Formatter__ in The Things Network. 

(Read on to learn how)

![CBOR Payload Formatter for The Things Network](https://lupyuen.github.io/images/payload-title.jpg)

# Payload Formatter

_What's a Payload Formatter in The Things Network?_

A __Payload Formatter__ is JavaScript Code that we configure in The Things Network to __decode the Sensor Data__ in the LoRaWAN Message Payload.

For PineDio Stack our Sensor Data is encoded with CBOR (Concise Binary Object Representation), so we use this __CBOR Payload Formatter__...

-   [__"CBOR Payload Formatter for The Things Network"__](https://lupyuen.github.io/articles/payload)

_Is it mandatory to use a Payload Formatter?_

Yes, our MQTT Gateway will work only if we __configure a suitable Payload Formatter__ that will decode our Sensor Data.

[(More about Payload Formatters)](https://lupyuen.github.io/articles/payload#whats-a-payload-formatter)

_What if we can't find a suitable Payload Formatter?_

We can make one together! [Post a comment here](https://www.reddit.com/r/TheThingsNetwork/comments/qafzu4/cbor_payload_formatter_for_the_things_network/?utm_source=share&utm_medium=web2x&context=3)

## Checkpoint Alpha

Let's verify that our __Payload Formatter works OK__ for decoding our Sensor Data...

1.  Start the __LoRaWAN Firmware__ on our LoRaWAN Device (PineDio Stack).

    Transmit some Sensor Data every minute...

    [__"Run the LoRaWAN Firmware"__](https://lupyuen.github.io/articles/tsen#run-the-lorawan-firmware)

1.  Log on to __The Things Network Console__

1.  Click __Applications → (Your Application) → Live Data__

1.  Our __Decoded Sensor Data__ should appear in the Live Data Table like so...

    ```json
    Payload: { l: 4000, t: 4669 }
    ```

    ![Decoded Sensor Data in the Live Data Table](https://lupyuen.github.io/images/payload-ttn3.png)

1.  Click on a message in the __Live Data Table__. 

    We should see the __decoded_payload__ field containing our Decoded Sensor Data...

    ```json
    {
      ...
      "uplink_message": {
        ...
        "decoded_payload": {
          "l": 4000,
          "t": 4656
        }    
    ```

Also verify that the __MQTT Server works OK__ at The Things Network...

1.  Start our __LoRaWAN Firmware__ and transmit Sensor Data every minute

    [(Like this)](https://lupyuen.github.io/articles/tsen#run-the-lorawan-firmware)

1.  Copy the __MQTT Public Address, Username and Password__ from The Things Network...

    [__"Configure The Things Network MQTT"__](https://lupyuen.github.io/articles/grafana#configure-the-things-network-mqtt)

1.  Install the __command-line tools for MQTT__...

    [__"Download Eclipse Mosquitto"__](https://mosquitto.org/download/)

1.  Enter this at the command line...

    ```bash
    ## Change au1.cloud.thethings.network to our 
    ## MQTT Public Address (without the port number)
    ## Change YOUR_USERNAME to our MQTT Username
    ## Change YOUR_PASSWORD to our MQTT Password

    ## For macOS and Linux:
    mosquitto_sub \
      -h au1.cloud.thethings.network \
      -t "#" \
      -u "YOUR_USERNAME" \
      -P "YOUR_PASSWORD" \
      -d

    ## For Windows:
    "c:\Program Files\Mosquitto\mosquitto_sub" ^
      -h au1.cloud.thethings.network ^
      -t "#" ^
      -u "YOUR_USERNAME" ^
      -P "YOUR_PASSWORD" ^
      -d
    ```

1.  We should see the __Uplink Messages transmitted__ by our LoRaWAN Device...

    ```json
    {
      ...
      "uplink_message": {
        ...
        "decoded_payload": {
          "l": 4000,
          "t": 4656
        }    
    ```

    Including __decoded_payload__ and the Decoded Sensor Data.

    [(See the complete message)](https://github.com/lupyuen/cbor-the-things-network#mqtt-log)

![MQTT Gateway for Prometheus](https://lupyuen.github.io/images/prometheus-flow2.jpg)

# MQTT Gateway for Prometheus

Now we connect our MQTT Gateway to The Things Network...

-   [__MQTT2Prometheus MQTT Gateway__](https://github.com/hikhvar/mqtt2prometheus)

Our MQTT Gateway shall...

-   __Subscribe to all MQTT Topics__ published on The Things Network

    (Including the Uplink Messages transmitted by our device)

-   __Ingest the Decoded Sensor Data__ from the Uplink Messages

    (As Prometheus Metrics)

Follow these steps to __configure our MQTT Gateway__...

1.  Download the __MQTT Gateway Configuration File__...

    [__ttn-mqtt.yaml__](https://github.com/lupyuen/prometheus-the-things-network/blob/main/ttn-mqtt.yaml)

1.  Edit the file. Fill in the __MQTT Public Address, Username and Password__ for The Things Network [(from here)](https://lupyuen.github.io/articles/grafana#configure-the-things-network-mqtt)...

    ```yaml    
    ## Change au1.cloud.thethings.network to our MQTT Public Address
    server: tcp://au1.cloud.thethings.network:1883

    ## Change luppy-application@ttn to our MQTT Username
    user: luppy-application@ttn

    ## Change YOUR_API_KEY to our MQTT Password
    password: YOUR_API_KEY
    ```

1.  Note that we're subscribing to __all MQTT Topics__...

    ```yaml
    ## Topic path to subscribe to. "#" means All Topics.
    topic_path: "#"
    ```

1.  Our MQTT Gateway shall extract the __Device ID__ from the MQTT Topic Path...

    ```yaml
    ## Extract the device ID (eui-YOUR_DEVICE_EUI) 
    ## from the topic path, which looks like...
    ## v3/luppy-application@ttn/devices/eui-YOUR_DEVICE_EUI/up
    device_id_regex: "(.*/)?devices/(?P<deviceid>.*)/.*"
    ```

    (Which will be helpful for filtering our Sensor Data by Device ID in Grafana)

    ![MQTT Configuration File](https://lupyuen.github.io/images/prometheus-config4.png)

## Prometheus Metrics

_What's a Prometheus Metric?_

A Metric is an item of __Monitoring Data__ that's collected and reported by Prometheus.

(Think of Metrics like CPU Usage and RAM Utilisation... Prometheus was originally created for monitoring servers)

In this article we shall use "Sensor Data" and "Metric" interchangeably, since Prometheus treats our __Sensor Data as Metrics__.

Let's define the Sensor Data / Metrics that will be __ingested by our MQTT Gateway__...

1.  Edit [__ttn-mqtt.yaml__](https://github.com/lupyuen/prometheus-the-things-network/blob/main/ttn-mqtt.yaml)

    Look for the __metrics__ section...

    ![Prometheus Metrics for MQTT Gateway](https://lupyuen.github.io/images/prometheus-config5.png)

1.  We define the __Metric for Temperature__ like so...

    ```yaml
    ## Temperature Metric
    ## Name of the metric in prometheus
    - prom_name: t

      ## JSON Path of the metric in our MQTT JSON message
      mqtt_name: "uplink_message.decoded_payload.t"

      ## Prometheus help text for this metric
      help: "Temperature"

      ## Prometheus type for this metric.
      ## Valid values are: "gauge" and "counter"
      type: gauge

      ## Map of string to string for constant labels.
      ## The labels will be attached to every Prometheus metric.
      const_labels:
        sensor_type: t    
    ```

1.  This tells MQTT Gateway: Our LoRaWAN Device (PineDio Stack) transmits a __Temperature Value__ (named "t") at this JSON Path...

    ```javascript
    uplink_message.decoded_payload.t
    ```

    Which matches our __JSON Message Format__ from Checkpoint Alpha...

    ```json
    {
      ...
      "uplink_message": {
        ...
        "decoded_payload": {
          "l": 4000,
          "t": 4656
        }    
    ```

    [(Our Temperature Values are scaled up 100 times... `4656` means `46.56` ºC)](https://lupyuen.github.io/articles/cbor#floating-point-numbers)

    ![Prometheus Metrics for MQTT Gateway](https://lupyuen.github.io/images/prometheus-config7.png)

1.  We define other Metrics the same way, like this __Light Level Metric__ that's transmitted by PineDio Stack...

    ```yaml
    ## Light Level Metric
    ## Name of the metric in prometheus
    - prom_name: l

      ## JSON Path of the metric in our MQTT JSON message
      mqtt_name: "uplink_message.decoded_payload.l"

      ## Prometheus help text for this metric
      help: "Light Level"

      ## Prometheus type for this metric.
      ## Valid values are: "gauge" and "counter"
      type: gauge

      ## Map of string to string for constant labels.
      ## The labels will be attached to every Prometheus metric.
      const_labels:
        sensor_type: l
    ```

## Start MQTT Gateway

We're ready to __start our MQTT Gateway__!

Follow these steps to download and run __MQTT2Prometheus__...

1.  Install the __latest version of Go__...

    [__`golang.org`__](https://golang.org)

1.  Enter this at the command line...

    ```bash
    ## Download mqtt2prometheus
    go get github.com/hikhvar/mqtt2prometheus

    ## For macOS and Linux:
    cd $GOPATH/src/github.com/hikhvar/mqtt2prometheus

    ## For Windows:
    cd %GOPATH%\src\github.com\hikhvar\mqtt2prometheus

    ## Build mqtt2prometheus
    go build ./cmd

    ## Run mqtt2prometheus.
    ## Change "ttn-mqtt.yaml" to the full path of our
    ## MQTT Gateway Configuration File.
    go run ./cmd -log-level debug -config ttn-mqtt.yaml
    ```

1.  We should see our MQTT Gateway __ingesting Sensor Data__ from The Things Network...

    ```text
    mqttclient/mqttClient.go:20     
    Connected to MQTT Broker

    mqttclient/mqttClient.go:21     
    Will subscribe to topic{"topic": "#"}

    web/tls_config.go:191           
    {"level": "info", "msg": "TLS is disabled.", "http2": false}

    metrics/ingest.go:42    
    Got message     
    {"topic": "v3/luppy-application@ttn/devices/eui-YOUR_DEVICE_EUI/up", "payload": 
    {
      ...
      "uplink_message": {
        "decoded_payload": {
          "l": 4000,
          "t": 5017
        }
    ```

## Checkpoint Bravo

Let's check the __Sensor Data ingested__ by our MQTT Gateway...

1.  Start our __LoRaWAN Firmware__ and transmit Sensor Data every minute

    [(Like this)](https://lupyuen.github.io/articles/tsen#run-the-lorawan-firmware)

1.  Enter this at the command-line...

    ```bash
    curl -v http://localhost:9641/metrics
    ```

1.  TODO

    ![Checking the metrics ingested by MQTT Gateway](https://lupyuen.github.io/images/prometheus-metric3.png)

    ![Prometheus Time Series Database](https://lupyuen.github.io/images/prometheus-flow3.jpg)

# Prometheus Time Series Database

TODO

![](https://lupyuen.github.io/images/prometheus-config6.png)

## Checkpoint Charlie

TODO

![](https://lupyuen.github.io/images/prometheus-metric2.png)

# Grafana Dashboard

TODO

![](https://lupyuen.github.io/images/prometheus-flow4.jpg)

TODO15

![](https://lupyuen.github.io/images/prometheus-grafana5.png)

TODO16

![](https://lupyuen.github.io/images/prometheus-grafana6.png)

## Checkpoint Delta

TODO

![Monitoring Devices on The Things Network with Prometheus and Grafana](https://lupyuen.github.io/images/prometheus-grafana4.png)

# MQTT with TLS Encryption

TODO11

![](https://lupyuen.github.io/images/prometheus-tls.png)

## Checkpoint Echo

TODO

![](https://lupyuen.github.io/images/prometheus-wireshark2.png)

# Prometheus Alerts

TODO

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/prometheus.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/prometheus.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1450262680795713538)

