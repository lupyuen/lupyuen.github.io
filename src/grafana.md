# Grafana Data Source for The Things Network

📝 _30 Sep 2021_

[__The Things Network__](https://lupyuen.github.io/articles/ttn) is a public global __wireless network for IoT devices__...

(And it's free for fair use!)

[__Grafana__](https://grafana.com/oss/grafana/) is a open source tool for __visualising all kinds of real-time data__...

(Works on Linux, macOS and Windows)

_Can we connect Grafana to The Things Network..._

_And instantly visualise the Sensor Data from our IoT Devices?_

![Visualising The Things Network Sensor Data with Grafana](https://lupyuen.github.io/images/grafana-flow.jpg)

Today we shall experiment with a custom __MQTT Data Source__ for Grafana that will stream real-time Sensor Data from The Things Network.

_Wait... We're streaming the Sensor Data without storing it?_

Yep this __streaming setup for Grafana__ requires fewer components because it doesn't store the data.

But it has limitations, which we'll discuss shortly.

(This is work-in-progress, some spot may get rough. And please pardon my ghastly GoLang 🙏)

![Grafana visualising Sensor Data from The Things Network](https://lupyuen.github.io/images/grafana-title.jpg)

_Grafana visualising Sensor Data from The Things Network_

# Configure The Things Network MQTT

Previously we have __configured our IoT Device__ in The Things Network...

-   [__"The Things Network on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/ttn)

Now we __enable the MQTT Server__ in The Things Network by clicking...

-   __Application__ → _(Your Application)_ → __Integrations__ → __MQTT__

![Configure The Things Network MQTT Server](https://lupyuen.github.io/images/grafana-ttn.png)

Click __"Generate New API Key"__ and copy the values for...

-   __Public Address__

    (We won't be using the Public TLS Address since our Data Source doesn't support TLS)

-   __Username__

-   __Password__

    (This is the only time we can see the password. Don't forget to copy it!)

We'll use the values in the next chapter.

## Test The Things Network MQTT

To __test the MQTT Server__ at The Things Network, enter this command...

```bash
## Change au1.cloud.thethings.network to our MQTT Public Address
## Change luppy-application@ttn to our MQTT Username
mosquitto_sub -h au1.cloud.thethings.network -t "#" -u "luppy-application@ttn" -P "YOUR_API_KEY" -d
```

MQTT JSON Messages will appear whenever our IoT Device joins the network or transmits data.

[(See sample MQTT Log)](https://github.com/lupyuen/the-things-network-datasource#mqtt-log)

[(More about The Things Network MQTT)](https://www.thethingsindustries.com/docs/integrations/mqtt/)

# Configure Grafana Data Source

TODO

-   [__lupyuen/the-things-network-datasource__](https://github.com/lupyuen/the-things-network-datasource)

TODO

1. In Grafana from the left-hand menu, navigate to **Configuration** > **Data sources**.
2. From the top-right corner, click the **Add data source** button.
3. Search for "The Things Network" in the search field, and hover over "The Things Network" search result.
4. Click the **Select** button for "The Things Network".

![](https://lupyuen.github.io/images/grafana-datasource2.png)

[Add the Data Source](https://grafana.com/docs/grafana/latest/datasources/add-a-data-source/) for "The Things Network"

Configure the Data Source with the values from `The Things Network → Application → (Your Application) → Integrations → MQTT`...

Basic fields:

| Field | Description                                        |
| ----- | -------------------------------------------------- |
| Name  | Name for this data source |
| Host  | Public Address of our MQTT Server at The Things Network |
| Port  | MQTT Port (default 1883) |

Authentication fields:

| Field    | Description                                                       |
| -------- | ----------------------------------------------------------------- |
| Username | Username for our MQTT Server at The Things Network |
| Password | Password for our MQTT Server at The Things Network |

![Configuring the Grafana Data Source for The Things Network](https://lupyuen.github.io/images/grafana-config.png)

TODO6

![](https://lupyuen.github.io/images/grafana-config2.png)

# Grafana Dashboard

TODO

Only one topic is supported: "`all`"

![](https://lupyuen.github.io/images/grafana-datasource3.png)

TODO

![](https://lupyuen.github.io/images/grafana-dashboard2.png)

TODO

![](https://lupyuen.github.io/images/grafana-filter.png)

# CBOR: Concise Binary Object Representation

TODO

We assume that Message Payloads are encoded in [__CBOR Format__](https://en.wikipedia.org/wiki/CBOR)...

```json
{ "t": 1234 }
```

(Multiple fields are OK)

![](https://lupyuen.github.io/images/grafana-cbor.png)

[(Source)](http://cbor.me/)

TODO2

![](https://lupyuen.github.io/images/grafana-cbor2.png)

TODO

![](https://lupyuen.github.io/images/grafana-payload.jpg)

# Transform MQTT Messages

TODO

-   [__lupyuen/the-things-network-datasource__](https://github.com/lupyuen/the-things-network-datasource)

This Data Source is based on the MQTT data source for Grafana...

-   [github.com/grafana/mqtt-datasource](https://github.com/grafana/mqtt-datasource)

TODO

![](https://lupyuen.github.io/images/grafana-code.png)

TODO4

![](https://lupyuen.github.io/images/grafana-code2.png)

TODO

![](https://lupyuen.github.io/images/grafana-test.png)

# Troubleshooting

TODO

To __enable Debug Logs__, edit...

```text
C:\Program Files\GrafanaLabs\grafana\conf\defaults.ini
```

And set...

```text
[log]
level = debug
```

In case of problems, check the __Grafana Log__ at...

```text
C:\Program Files\GrafanaLabs\grafana\data\log\grafana.log
```

[(See sample Grafana Log)](https://github.com/lupyuen/the-things-network-datasource#grafana-log)

# Store Data with Prometheus

TODO

![](https://lupyuen.github.io/images/grafana-flow2.jpg)

# What's Next

TODO

PineDio Stack BL604

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/grafana.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/grafana.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1440459917828050946)

# Appendix: Install Grafana and Data Source

TODO

-   [__lupyuen/the-things-network-datasource__](https://github.com/lupyuen/the-things-network-datasource)

TODO

## Install Grafana

TODO

https://grafana.com/ -> Self-Managed -> Download Grafana

Edition: OSS

Download for Linux, macOS, Windows, Arm and Docker

http://localhost:3000/

-   Username: admin

-   Password: admin

## Build Data Source

TODO

(Note: This Data Source uses the Grafana Live Streaming API, please use Grafana version 8.0 or later)

Set permissions: `Users` should be granted `Full Control`

![](https://lupyuen.github.io/images/grafana-permission.png)

This Data Source should be located in the __Grafana Plugins Folder__...

```bash
##  For Windows:
cd C:\Program Files\GrafanaLabs\grafana\data\plugins

git clone --recursive https://github.com/lupyuen/the-things-network-datasource
```

Refer to: [Building a Streaming Datasource Backend Plugin](https://grafana.com/tutorials/build-a-streaming-data-source-plugin/)

Details: [Ubuntu](https://github.com/grafana/mqtt-datasource/issues/15#issuecomment-894477802) [Windows](https://github.com/grafana/mqtt-datasource/issues/15#issuecomment-894534196)

To __build the Data Source__...

```bash
yarn install
yarn build
```

[(See the Build Log)](https://github.com/lupyuen/the-things-network-datasource#build-log)

NOTE: The `yarn build` command above might fail on a non-unix-like system, like Windows, where you can try replacing the `rm -rf` command with `rimraf` in the `./package.json` file to make it work.

3. Run `mage reloadPlugin` or restart Grafana for the Data Source to load.

## Enable Data Source

To __enable the Data Source__, edit...

```text
C:\Program Files\GrafanaLabs\grafana\conf\defaults.ini
```

And set...

```text
[plugins]
allow_loading_unsigned_plugins = the-things-network-datasource
```

To __enable Debug Logs__, set...

```text
[log]
level = debug
```

In case of problems, check the __Grafana Log__ at...

```text
C:\Program Files\GrafanaLabs\grafana\data\log\grafana.log
```

[(See sample Grafana Log)](https://github.com/lupyuen/the-things-network-datasource#grafana-log)
