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

Let's __render the Sensor Data__ from The Things Network in Grafana!

Click __"Add Panel"__ (top right)

Click __"Add An Empty Panel"__

![Add Panel](https://lupyuen.github.io/images/grafana-dashboard3.png)

Set the __Data Source__ to __"The Things Network"__

Set the __Topic__ to __"all"__

![Set Data Source and Topic](https://lupyuen.github.io/images/grafana-dashboard7.png)

Click __"Apply"__ (top right)

Our Sensor Data appears on the Grafana Dashboard!

![The Things Network Dashboard](https://lupyuen.github.io/images/grafana-dashboard6.png)

## View Raw Data

To see the __Raw Sensor Data__ as a table...

Click __"Panel Title"__ and __"Edit"__

Click __"Table View"__

![Table View](https://lupyuen.github.io/images/grafana-dashboard4.png)

## Filter Data

To __filter the Sensor Data__ that will be rendered in the dashboard...

Click the __"Transform"__ Tab

Select __"Filter Data By Values"__

Set the Conditions and click __"Apply"__

![Filter Data](https://lupyuen.github.io/images/grafana-dashboard8.png)

The above filter matches the __Device ID__ with the Regular Expression...

```text
eui-70b3.*
```

Which means that only Device IDs starting with __"eui-70b3"__ will be rendered.

# CBOR: Concise Binary Object Representation

TODO

We assume that Message Payloads are encoded in [__CBOR Format__](https://en.wikipedia.org/wiki/CBOR)...

```json
{ 
  "t": 1234, 
  "l": 2345 
}
```

![](https://lupyuen.github.io/images/grafana-cbor4.jpg)

[(Source)](http://cbor.me/)

## Decode CBOR in Go

TODO

```go
import "github.com/fxamacker/cbor/v2"

//  Encoded CBOR payload for { "t": 1234, "l": 2345 }
payload := []byte{0xa2, 0x61, 0x74, 0x19, 0x04, 0xd2, 0x61, 0x6c, 0x19, 0x09, 0x29}

//  Decode CBOR payload to a map of String -> interface{}
var body map[string]interface{}
err := cbor.Unmarshal(payload, &body)

//  Shows: map[l:2345 t:1234]
if err == nil {
  fmt.Printf("%v\n", body)
}
```

![](https://lupyuen.github.io/images/grafana-cbor2.png)

TODO

![](https://lupyuen.github.io/images/grafana-payload.jpg)

# MQTT Integration

TODO

-   [__lupyuen/the-things-network-datasource__](https://github.com/lupyuen/the-things-network-datasource)

Our Data Source is based on the MQTT Data Source for Grafana...

-   [__grafana/mqtt-datasource__](https://github.com/grafana/mqtt-datasource)

TODO

## Subscribe to MQTT

TODO

From [pkg/mqtt/client.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/mqtt/client.go#L150-L165)

```go
func (c *Client) Subscribe(t string) {
  if _, ok := c.topics.Load(t); ok {
    return
  }
  //  Subscribe to all topics: "#". TODO: Support other topics.
  //  Previously: log.DefaultLogger.Debug(fmt.Sprintf("Subscribing to MQTT topic: %s", t))
  log.DefaultLogger.Debug(fmt.Sprintf("Subscribing to MQTT topic: %s", defaultTopicMQTT))
  topic := Topic{
    path: t,
  }
  c.topics.Store(&topic)

  //  Subscribe to all topics: "#". TODO: Support other topics.
  //  Previously: c.client.Subscribe(t, 0, c.HandleMessage)
  c.client.Subscribe(defaultTopicMQTT, 0, c.HandleMessage)
}
```

## Receive MQTT Messages

TODO

From [pkg/mqtt/client.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/mqtt/client.go#L96-L148)

```go
func (c *Client) HandleMessage(_ paho.Client, msg paho.Message) {
  log.DefaultLogger.Debug(fmt.Sprintf("Received MQTT Message for topic %s", msg.Topic()))
  //  Accept all topics as "all". TODO: Support other topics.
  //  Previously: topic, ok := c.topics.Load(msg.Topic())
  topic, ok := c.topics.Load(defaultTopicName)
  if !ok {
    log.DefaultLogger.Debug(fmt.Sprintf("Topic not found: %s", defaultTopicName))
    return
  }

  //  Compose message
  message := Message{
    Timestamp: time.Now(),
    Value:     string(msg.Payload()),
  }

  //  TODO: Fix this hack to reject messages without a valid CBOR Base64 Payload.
  //  CBOR Payloads must begin with a CBOR Map: 0xA1 or 0xA2 or 0xA3 or ...
  //  So the Base64 Encoding must begin with "o" or "p" or "q" or ...
  //  We stop at 0xB1 (Base64 "s") because we assume LoRaWAN Payloads will be under 50 bytes.
  //  Join Messages don't have a payload and will also be rejected.
  const frm_payload = "\"frm_payload\":\""
  if !strings.Contains(message.Value, frm_payload+"o") &&
    !strings.Contains(message.Value, frm_payload+"p") &&
    !strings.Contains(message.Value, frm_payload+"q") &&
    !strings.Contains(message.Value, frm_payload+"r") &&
    !strings.Contains(message.Value, frm_payload+"s") {
    log.DefaultLogger.Debug(fmt.Sprintf("Missing or invalid payload: %s", message.Value))
    return
  }

  // store message for query
  topic.messages = append(topic.messages, message)

  // limit the size of the retained messages
  if len(topic.messages) > 1000 {
    topic.messages = topic.messages[1:]
  }

  c.topics.Store(topic)

  //  Stream message to topic "all". TODO: Support other topics.
  //  Previously: streamMessage := StreamMessage{Topic: msg.Topic(), Value: string(msg.Payload())}
  streamMessage := StreamMessage{Topic: defaultTopicName, Value: string(msg.Payload())}

  log.DefaultLogger.Debug(fmt.Sprintf("Stream MQTT Message for topic %s", defaultTopicName))

  select {
  case c.stream <- streamMessage:
  default:
    // don't block if nothing is reading from the channel
  }
}
```

# Transform MQTT Messages

TODO

From [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L19-L44)

```go
func ToFrame(topic string, messages []mqtt.Message) *data.Frame {
  log.DefaultLogger.Debug(fmt.Sprintf("ToFrame: topic=%s", topic))

  count := len(messages)
  if count > 0 {
    first := messages[0].Value
    if strings.HasPrefix(first, "{") {
      return jsonMessagesToFrame(topic, messages)
    }
  }

  // Fall through to expecting values
  timeField := data.NewFieldFromFieldType(data.FieldTypeTime, count)
  timeField.Name = "Time"
  valueField := data.NewFieldFromFieldType(data.FieldTypeFloat64, count)
  valueField.Name = "Value"

  for idx, m := range messages {
    if value, err := strconv.ParseFloat(m.Value, 64); err == nil {
      timeField.Set(idx, m.Timestamp)
      valueField.Set(idx, value)
    }
  }

  return data.NewFrame(topic, timeField, valueField)
}
```

From [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L46-L129)

```go
//  Transform the array of MQTT Messages (JSON encoded) into a Grafana Data Frame.
//  See sample messages: https://github.com/lupyuen/the-things-network-datasource#mqtt-log
func jsonMessagesToFrame(topic string, messages []mqtt.Message) *data.Frame {
  //  Quit if no messages to transform
  count := len(messages)
  if count == 0 {
    log.DefaultLogger.Debug(fmt.Sprintf("jsonMessagesToFrame: No msgs for topic=%s", topic))
    return nil
  }

  //  Transform the first message
  msg := messages[0]
  log.DefaultLogger.Debug(fmt.Sprintf("jsonMessagesToFrame: topic=%s, msg=%s", topic, msg.Value))

  //  Decode the CBOR payload
  body, err := decodeCborPayload(msg.Value)
  if err != nil {
    return set_error(data.NewFrame(topic), err)
  }

  //  Construct the Timestamp field
  timeField := data.NewFieldFromFieldType(data.FieldTypeTime, count)
  timeField.Name = "Time"
  timeField.SetConcrete(0, msg.Timestamp)

  //  Create a field for each key and set the first value
  keys := make([]string, 0, len(body))
  fields := make(map[string]*data.Field, len(body))

  //  Compose the fields for the first row of the Data Frame
  for key, val := range body {
    //  Get the Data Frame Type for the field
    typ := get_type(val)

    //  Create the field for the first row
    field := data.NewFieldFromFieldType(typ, count)
    field.Name = key
    field.SetConcrete(0, val)
    fields[key] = field
    keys = append(keys, key)
  }
  sort.Strings(keys) // keys stable field order.

  //  Transform the messages after the first one
  for row, m := range messages {
    //  Skip the first message
    if row == 0 {
      continue
    }

    //  Decode the CBOR payload
    body, err := decodeCborPayload(m.Value)
    if err != nil {
      log.DefaultLogger.Debug(fmt.Sprintf("jsonMessagesToFrame: Decode error %s", err.Error()))
      continue
    }

    //  Set the Timestamp for the transformed row
    timeField.SetConcrete(row, m.Timestamp)

    //  Set the fields for the transformed row
    for key, val := range body {
      field, ok := fields[key]
      if ok {
        field.SetConcrete(row, val)
      }
    }
  }

  //  Construct the Data Frame
  frame := data.NewFrame(topic, timeField)

  //  Append the fields to the Data Frame
  for _, key := range keys {
    frame.Fields = append(frame.Fields, fields[key])
  }

  //  Dump the Data Frame
  log.DefaultLogger.Debug(fmt.Sprintf("jsonMessagesToFrame: Frame=%+v", frame))
  for _, field := range frame.Fields {
    log.DefaultLogger.Debug(fmt.Sprintf("  field=%+v", field))
  }
  return frame
}
```

From [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L231-L239)

```go
//  Return the Data Frame set to the given error
func set_error(frame *data.Frame, err error) *data.Frame {
  frame.AppendNotices(data.Notice{
    Severity: data.NoticeSeverityError,
    Text:     err.Error(),
  })
  log.DefaultLogger.Debug(err.Error())
  return frame
}
```

## Decode Payload

TODO

From [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L131-L190)

```go
//  Decode the CBOR payload in the JSON message.
//  See sample messages: https://github.com/lupyuen/the-things-network-datasource#mqtt-log
func decodeCborPayload(msg string) (map[string]interface{}, error) {
  //  Deserialise the message doc to a map of String -> interface{}
  var doc map[string]interface{}
  err := json.Unmarshal([]byte(msg), &doc)
  if err != nil {
    return nil, err
  }

  //  Get the Uplink Message
  uplink_message, ok := doc["uplink_message"].(map[string]interface{})
  if !ok {
    return nil, errors.New("uplink_message missing")
  }

  //  Get the Payload
  frm_payload, ok := uplink_message["frm_payload"].(string)
  if !ok {
    return nil, errors.New("frm_payload missing")
  }

  //  Base64 decode the Payload
  payload, err := base64.StdEncoding.DecodeString(frm_payload)
  if err != nil {
    return nil, err
  }
  log.DefaultLogger.Debug(fmt.Sprintf("payload: %v", payload))

  //  TODO: Testing CBOR Decoding for {"t": 1234}.  See http://cbor.me/
  //  if payload[0] == 0 {
  //  	payload = []byte{0xA1, 0x61, 0x74, 0x19, 0x04, 0xD2}
  //  	log.DefaultLogger.Debug(fmt.Sprintf("TODO: Testing payload: %v", payload))
  //  }

  //  Decode CBOR payload to a map of String -> interface{}
  var body map[string]interface{}
  err = cbor.Unmarshal(payload, &body)
  if err != nil {
    return nil, err
  }

  //  Add the Device ID to the body: end_device_ids -> device_id
  end_device_ids, ok := doc["end_device_ids"].(map[string]interface{})
  if ok {
    device_id, ok := end_device_ids["device_id"].(string)
    if ok {
      body["device_id"] = device_id
    }
  }

  //  TODO: Test various field types
  //  body["f64"] = float64(1234)
  //  body["u64"] = uint64(1234)
  //  body["str"] = "Test"

  //  Shows: map[device_id:eui-70b3d57ed0045669 t:1234]
  log.DefaultLogger.Debug(fmt.Sprintf("CBOR decoded: %v", body))
  return body, nil
}
```

## Convert Type

TODO

From [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L192-L229)

```go
//  Return the Data Frame Type for the CBOR decoded value
func get_type(val interface{}) data.FieldType {
  //  Based on https://github.com/fxamacker/cbor/blob/master/decode.go#L43-L53
  switch v := val.(type) {
  //  CBOR booleans decode to bool.
  case bool:
    return data.FieldTypeBool

  //  CBOR positive integers decode to uint64.
  case uint64:
    return data.FieldTypeNullableUint64

  //  CBOR negative integers decode to int64 (big.Int if value overflows).
  case int64:
    return data.FieldTypeInt64

  //  CBOR floating points decode to float64.
  case float64:
    return data.FieldTypeNullableFloat64

  //  CBOR text strings decode to string.
  case string:
    return data.FieldTypeNullableString

  //  CBOR times (tag 0 and 1) decode to time.Time.
  case time.Time:
    return data.FieldTypeNullableTime

  //  TODO: CBOR byte strings decode to []byte.
  //  TODO: CBOR arrays decode to []interface{}.
  //  TODO: CBOR maps decode to map[interface{}]interface{}.
  //  TODO: CBOR null and undefined values decode to nil.
  //  TODO: CBOR bignums (tag 2 and 3) decode to big.Int.
  default:
    log.DefaultLogger.Debug(fmt.Sprintf("Unknown type %T for %v", v, val))
    return data.FieldTypeUnknown
  }
}
```

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

## For macOS:
/usr/local/etc/grafana/grafana.ini

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

## For macOS:
/usr/local/var/log/grafana/grafana.log

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

    ##  For macOS: 
    cd /usr/local/var/lib/grafana/plugins

    ##  For Windows: Need to grant "Full Control" permission to "Users" group for this folder
    cd C:\Program Files\GrafanaLabs\grafana\data\plugins

    ##  Download source files for The Things Network Data Source
    git clone --recursive https://github.com/lupyuen/the-things-network-datasource
    ```

1.  Install the __Build Tools__...

    [__Build Tools for Linux (Ubuntu)__](https://github.com/grafana/mqtt-datasource/issues/15#issuecomment-894477802)

    [__Build Tools for macOS__](https://lupyuen.github.io/articles/grafana#appendix-install-build-tools-for-macos)

    [__Build Tools for Windows__](https://github.com/grafana/mqtt-datasource/issues/15#issuecomment-894534196)

    [(More details here)](https://grafana.com/tutorials/build-a-streaming-data-source-plugin/)

1.  __Build the Data Source__...

    ```bash
    ##  Install the dependencies
    cd the-things-network-datasource
    yarn install

    ##  Build the Data Source (React + Go)
    yarn build

    ##  If "mage" is not found, set the PATH
    export PATH=$PATH:$GOPATH/bin
    ```

    [(See the Build Log)](https://github.com/lupyuen/the-things-network-datasource#build-log)

1.  If "`yarn build`" fails on Windows, edit `package.json` and replace "`rm -rf`" by "`rimraf`"

1.  __Restart the Grafana Service__ for the Data Source to load

    ```bash
    ## For Ubuntu and WSL:
    sudo service grafana-server restart
    sudo service grafana-server status

    ## For macOS:
    brew services restart grafana

    ## For Windows: Run this as Administrator
    net stop grafana
    net start grafana
    ```

## Enable Data Source

1.  Edit the __Grafana Configuration File__...

    ```text
    ## For Linux:
    /usr/share/grafana/conf/defaults.ini

    ## For macOS:
    /usr/local/etc/grafana/grafana.ini

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

    ## For macOS:
    brew services restart grafana

    ## For Windows: Run this as Administrator
    net stop grafana
    net start grafana
    ```

1.  In case of problems, check the __Grafana Log__ at...

    ```text
    ## For Linux:
    /var/log/grafana/grafana.log

    ## For macOS:
    /usr/local/var/log/grafana/grafana.log

    ## For Windows:
    C:\Program Files\GrafanaLabs\grafana\data\log\grafana.log
    ```

    [(See sample Grafana Log)](https://github.com/lupyuen/the-things-network-datasource#grafana-log)

# Appendix: Install Build Tools for macOS

To install the tools for building our Grafana Data Source on macOS...

1.  Install __Node.js v14__ or later...

    [__`nodejs.org`__](https://nodejs.org)

1.  Install __Yarn__...

    ```bash
    npm install -g yarn
    ```

1.  Install __Go__...

    [__`golang.org`__](https://golang.org)

1.  Install __Mage__...

    ```bash
    go get -u -d github.com/magefile/mage
    pushd $GOPATH/src/github.com/magefile/mage
    go run bootstrap.go
    export PATH=$PATH:$GOPATH/bin
    mage -version
    popd
    ```
