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

-   __Applications__ → _(Your Application)_ → __Integrations__ → __MQTT__

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

Let's __add and configure__ our Grafana Data Source for The Things Network...

-   [__lupyuen/the-things-network-datasource__](https://github.com/lupyuen/the-things-network-datasource)

Follow these instructions to __install Grafana and the Data Source__ for The Things Network...

-   [__"Install Grafana and Data Source"__](https://lupyuen.github.io/articles/grafana#appendix-install-grafana-and-data-source)

In Grafana, click the left menu bar...

-   __Configuration__ → __Data Sources__

Click __"Add Data Source"__

![Add Data Source](https://lupyuen.github.io/images/grafana-datasource4.png)

Look for __"The Things Network"__ and click __"Select"__

![Data Source for The Things Network](https://lupyuen.github.io/images/grafana-datasource2.png)

Fill in the values copied from our __MQTT Server at The Things Network__...

-   __Name__: Use the default

-   __Host__: Public Address of our MQTT Server

-   __Port__: 1883

-   __Username__: Username for our MQTT Server

-   __Password__: Password for our MQTT Server

![Configuring the Grafana Data Source for The Things Network](https://lupyuen.github.io/images/grafana-config.png)

Click __"Save & Test"__

We should see the message __"MQTT Connected"__...

![MQTT Connected](https://lupyuen.github.io/images/grafana-config2.png)

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
## For Linux:
/usr/share/grafana/conf/defaults.ini

## For Windows:
C:\Program Files\GrafanaLabs\grafana\conf\defaults.ini
```

And set...

```text
[log]
level = debug
```

In case of problems, check the __Grafana Log__ at...

```text
## For Linux:
/var/log/grafana/grafana.log

## For Windows:
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

Here are the steps to install Grafana and our Data Source for The Things Network.

## Install Grafana

1.  Browse to [__grafana.com/oss/grafana__](https://grafana.com/oss/grafana/)

    Click __"Get Grafana → Self-Managed → Download Grafana"__

1.  For __"Edition"__ select __"OSS"__

1.  Click Linux, macOS, Windows, Arm or Docker

    (Grafana for Linux works on WSL too)

1.  Follow the instructions to download and install Grafana

1.  For Linux and macOS: Start the Grafana Server

    ```bash
    ## For Ubuntu and WSL
    sudo service grafana-server restart
    sudo service grafana-server status

    ## For macOS
    brew services start grafana
    ```

1.  To test Grafana, browse to 

    __`http://localhost:3000`__

    __Username:__ admin

    __Password:__ admin

## Build Data Source

(Note: Our Data Source uses the Grafana Live Streaming API, please use Grafana version 8.0 or later)

1.  For Windows: Grant __`Full Control`__ permission to the __`Users`__ group for the Grafana Plugins Folder...

    ```text
    C:\Program Files\GrafanaLabs\grafana\data\plugins
    ```

    ![Permissions for plugins folder](https://lupyuen.github.io/images/grafana-permission.png)


1.  __Download the Data Source__ into the Grafana Plugins Folder...

    ```bash
    ##  For Linux: Need "sudo" to access this folder
    cd /var/lib/grafana/plugins

    ##  For Windows: Need to grant "Full Control" permission to "Users" group for this folder
    cd C:\Program Files\GrafanaLabs\grafana\data\plugins

    ##  Download source files for The Things Network Data Source
    git clone --recursive https://github.com/lupyuen/the-things-network-datasource
    ```

1.  Install the __Build Tools__...

    [__Build Tools for Ubuntu__](https://github.com/grafana/mqtt-datasource/issues/15#issuecomment-894477802)

    [__Build Tools for Windows__](https://github.com/grafana/mqtt-datasource/issues/15#issuecomment-894534196)

    [(More details here)](https://grafana.com/tutorials/build-a-streaming-data-source-plugin/)

1.  __Build the Data Source__...

    ```bash
    ##  Install the dependencies
    cd the-things-network-datasource
    yarn install

    ##  Build the Data Source (React + Go)
    yarn build
    ```

    [(See the Build Log)](https://github.com/lupyuen/the-things-network-datasource#build-log)

1.  If "`yarn build`" fails on Windows, edit `package.json` and replace "`rm -rf`" by "`rimraf`"

1.  __Restart the Grafana Service__ for the Data Source to load

## Enable Data Source

1.  Edit the __Grafana Configuration File__...

    ```text
    ## For Linux:
    /usr/share/grafana/conf/defaults.ini

    ## For Windows:
    C:\Program Files\GrafanaLabs\grafana\conf\defaults.ini
    ```

1.  To __enable our Data Source__, set...

    ```text
    [plugins]
    allow_loading_unsigned_plugins = the-things-network-datasource
    ```

1.  To __enable Debug Logs__, set...

    ```text
    [log]
    level = debug
    ```

1.  __Restart the Grafana Service__ for the Data Source to load

    ```bash
    ## For Ubuntu and WSL:
    sudo service grafana-server restart
    sudo service grafana-server status

    ## For Windows: Run this as Administrator
    net stop grafana
    net start grafana
    ```

1.  In case of problems, check the __Grafana Log__ at...

    ```text
    ## For Linux:
    /var/log/grafana/grafana.log

    ## For Windows:
    C:\Program Files\GrafanaLabs\grafana\data\log\grafana.log
    ```

    [(See sample Grafana Log)](https://github.com/lupyuen/the-things-network-datasource#grafana-log)

# Appendix: Install Build Tools for macOS

TODO

1.  Install __Node v14__ or later...

1.  Install __Yarn__...

1.  Install __Go__...

1.  Install __Mage__...

    ```bash
    $ go get -u -d github.com/magefile/mage
    $ cd $GOPATH/src/github.com/magefile/mage
    $ go run bootstrap.go
    $ mage -version
    Mage Build Tool v1.11.0-2-g4cf3cfc
    Build Date: 2021-08-03T11:57:28-07:00
    Commit: 4cf3cfc
    built with: go1.13.8
    ```
