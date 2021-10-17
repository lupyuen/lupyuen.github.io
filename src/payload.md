# CBOR Payload Formatter for The Things Network

📝 _24 Oct 2021_

Suppose we have an __IoT Sensor Device__ (like [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio)) connected to __The Things Network__ (via LoRaWAN)...

-   [__"The Things Network on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/ttn)

And our device __transmits Sensor Data__ to The Things Network in __CBOR Format__ (because it requires fewer bytes than JSON)...

-   [__"Encode Sensor Data with CBOR on BL602"__](https://lupyuen.github.io/articles/cbor)

> ![IoT Sensor Device transmits CBOR Sensor Data to The Things Network](https://lupyuen.github.io/images/grafana-flow3.jpg)

_How shall we process the CBOR Sensor Data transmitted by our device?_

We could let __each Application fetch and decode__ the CBOR Sensor Data from The Things Network...

![Each Application fetches and decodes the CBOR Sensor Data from The Things Network](https://lupyuen.github.io/images/payload-flow3.jpg)

Like we've done for Grafana and Roblox...

-   [__"Grafana Data Source for The Things Network"__](https://lupyuen.github.io/articles/grafana)

-   [__"IoT Digital Twin with Roblox and The Things Network"__](https://lupyuen.github.io/articles/roblox)

_Erm this solution doesn't scale well if we have many Applications..._

Exactly! For every Application that we add (like Prometheus), we would need to __decode the CBOR Sensor Data again and again__.

_What's the right solution then?_

The proper solution is to configure a __Payload Formatter__ at The Things Network that will __decode our CBOR Sensor Data once__...

![CBOR Payload Formatter for The Things Network](https://lupyuen.github.io/images/payload-title.jpg)

And __distribute the Decoded Sensor Data__ to all Applications.

TODO

# TODO

TODO1

![](https://lupyuen.github.io/images/payload-cbor.png)

TODO2

![](https://lupyuen.github.io/images/payload-code3.png)

TODO3

![](https://lupyuen.github.io/images/payload-code4.png)

TODO5

![](https://lupyuen.github.io/images/payload-config2.png)

TODO8

![](https://lupyuen.github.io/images/payload-formatter.png)

TODO9

![](https://lupyuen.github.io/images/payload-formatter2.png)

TODO10

![](https://lupyuen.github.io/images/payload-ttn3.png)

TODO11

![](https://lupyuen.github.io/images/payload-ttn4.png)

![Storing The Things Network Sensor Data with Prometheus](https://lupyuen.github.io/images/grafana-flow2.jpg)

[(Source)](https://lupyuen.github.io/articles/grafana#store-data-with-prometheus)

# What's Next

TODO

Today we have turned BL602 and BL604 into a basic __IoT Sensor Device__ that transmits its Internal Temperature to __LoRaWAN and The Things Network__.

In the next article we shall revisit Grafana and The Things Network... And build a better __IoT Monitoring System__ that stores the [__Sensor Data with Prometheus__](https://lupyuen.github.io/articles/grafana#store-data-with-prometheus).

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/payload.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/payload.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1448846003608567809)
