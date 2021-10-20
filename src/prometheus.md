# Monitor IoT Devices in The Things Network with Prometheus and Grafana

📝 _27 Oct 2021_

Suppose we have some __IoT Devices__ that transmit __Sensor Data__ (via LoRa and LoRaWAN) to __The Things Network__...

[(That's the free-to-use public global wireless network for IoT Devices)](https://lupyuen.github.io/articles/ttn)

> ![IoT Devices transmitting Sensor Data to The Things Network](https://lupyuen.github.io/images/grafana-flow3.jpg)

_How would we monitor the Sensor Data transmitted by the IoT Devices?_

TODO

![](https://lupyuen.github.io/images/prometheus-title.jpg)

TODO

1.  MQTT: TODO

1.  MQTT Gateway: TODO

1.  Prometheus: TODO

    (Because Prometheus works great for storing and querying IoT Sensor Data)

1.  Grafana: TODO

    (Because Grafana works well with Prometheus for charting IoT Sensor Data)

Here's the outcome...

![Monitoring Devices on The Things Network with Prometheus and Grafana](https://lupyuen.github.io/images/prometheus-grafana4.png)

TODO

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

Today we'll demo this Prometheus + Grafana Integration with __PineDio Stack BL604 RISC-V Board__ (pic above)

-   [__"The Things Network on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/ttn)

But it should work for __any LoRaWAN Device__ connected to The Things Network...

Assuming that we have a suitable __Payload Formatter__ configured in The Things Network. Read on to learn more...

![CBOR Payload Formatter for The Things Network](https://lupyuen.github.io/images/payload-title.jpg)

# Payload Formatter

TODO

[Post a comment here and let's solve it together!](https://www.reddit.com/r/TheThingsNetwork/comments/qafzu4/cbor_payload_formatter_for_the_things_network/?utm_source=share&utm_medium=web2x&context=3)

## Checkpoint Alpha

TODO

# MQTT Gateway for Prometheus

TODO

![](https://lupyuen.github.io/images/prometheus-flow3.jpg)

TODO

![](https://lupyuen.github.io/images/prometheus-flow2.jpg)

TODO10

![](https://lupyuen.github.io/images/prometheus-config7.png)

TODO14

![](https://lupyuen.github.io/images/prometheus-config4.png)

TODO12

![](https://lupyuen.github.io/images/prometheus-config5.png)

## Checkpoint Bravo

TODO

![](https://lupyuen.github.io/images/prometheus-metric3.png)

# Prometheus Time Series Database

TODO5

![](https://lupyuen.github.io/images/prometheus-flow.jpg)

TODO8

![](https://lupyuen.github.io/images/prometheus-flow5.jpg)

TODO13

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

