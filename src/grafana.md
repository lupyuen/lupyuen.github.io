# Grafana Data Source for The Things Network

📝 _27 Sep 2021_

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

_The Sensor Data we've seen earlier... Was it encoded as JSON?_

Not quite. If we encode the Sensor Data as __JSON__...

```json
{ 
  "t": 1234, 
  "l": 2345 
}
```

We'll need __19 bytes__ to transmit the Sensor Data.

Which might be __too much__ for The Things Network.

_What are the message limits for The Things Network?_

The Things Network is __Free for Fair Use__, with limits on the __size of messages__ and __how often__ we may send them.

If we expect to send 10 messages per hour, our Message Payload should not exceed __12 bytes__.

Thus our Message Payload is __too small for JSON!__ We'll encode with CBOR instead.

[(More about The Things Network limits)](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

_What is CBOR?_

[__Concise Binary Object Representation (CBOR)__](https://en.wikipedia.org/wiki/CBOR) works like a binary, compressed form of JSON...

![Sensor Data encoded as CBOR](https://lupyuen.github.io/images/grafana-cbor4.jpg)

Our Data Source for The Things Network assumes that the Message Payload is __encoded with CBOR__.

To experiment with CBOR, try the [__CBOR Playground__](http://cbor.me/)...

![CBOR Playground](https://lupyuen.github.io/images/grafana-cbor5.png)

[(More about CBOR implementations)](https://cbor.io/impls.html)

## Decode CBOR in Go

Our Data Source calls this __Go Library__ to decode CBOR Message Payloads...

-   [__fxamacker/cbor__](https://github.com/fxamacker/cbor)

We call the library like so...

```go
import "github.com/fxamacker/cbor/v2"

//  Encoded CBOR payload for { "t": 1234, "l": 2345 }
payload := []byte{0xa2, 0x61, 0x74, 0x19, 0x04, 0xd2, 0x61, 0x6c, 0x19, 0x09, 0x29}

//  Decode CBOR payload to a map of string → interface{}
var body map[string]interface{}
err := cbor.Unmarshal(payload, &body)

//  Shows: map[l:2345 t:1234]
if err == nil {
  fmt.Printf("%v\n", body)
}
```

Later we'll see the decoding logic in our Data Source.

## Message Payload

_Where is the Message Payload?_

Our __CBOR Message Payload__ is embedded deep inside the MQTT Message from The Things Network...

```json
{
  "end_device_ids": {
    "device_id": "eui-YOUR_DEVICE_EUI",
    "application_ids": {
      "application_id": "YOUR_APPLICATION_ID"
    },
    "dev_eui":  "YOUR_DEVICE_EUI",
    "join_eui": "0000000000000000",
    "dev_addr": "YOUR_DEV_ADDR"
  },
  "correlation_ids": [ ... ],
  "received_at":     "2021-09-25T13:46:17.083379844Z",
  "uplink_message":  {
    "session_key_id":  "YOUR_SESSION_KEY_ID",
    "f_port":          2,
    "frm_payload":     "omF0GQTSYWwZA+g=",
```

[(Source)](https://github.com/lupyuen/the-things-network-datasource#mqtt-log)

__frm_payload__ contains our CBOR Message Payload, __encoded with Base64__.

We'll watch the extraction of the Message Payload in a while.

> ![Message Payload in MQTT Message](https://lupyuen.github.io/images/grafana-payload.jpg)

# MQTT Integration

Let's look at the __Go Source Code__ for our Data Source...

-   [__lupyuen/the-things-network-datasource__](https://github.com/lupyuen/the-things-network-datasource)

Our Data Source is modded from the __MQTT Data Source for Grafana__...

-   [__grafana/mqtt-datasource__](https://github.com/grafana/mqtt-datasource)

## Subscribe to MQTT

Here's how our Data Source __subscribes to MQTT Topics__: [pkg/mqtt/client.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/mqtt/client.go#L150-L165)

```go
//  Name of our default topic
//  TODO: Support other topics
const defaultTopicName = "all"

//  We will subscribe to all MQTT topics
//  TODO: Support other topics
const defaultTopicMQTT = "#"

//  Subscribe to the topic.
//  We assume that the Topic Name is "all".
func (c *Client) Subscribe(t string) {
  //  If Topic Name already exists, quit
  if _, ok := c.topics.Load(t); ok {
    return
  }

  //  Create the topic: "all"
  topic := Topic{
    path: t,
  }
  c.topics.Store(&topic)

  //  Subscribe to all MQTT Topics: "#". TODO: Support other topics.
  //  Previously: c.client.Subscribe(t, 0, c.HandleMessage)
  c.client.Subscribe(defaultTopicMQTT, 0, c.HandleMessage)
}
```

Sorry this code looks wonky...

(Because I haven't decided which topics we should support)

1.  We subscribe to __all MQTT Topics__: "#"

    This means we will receive MQTT Messages for __all our devices__.

    Also we will receive __all types of messages__, including the "Join Network" messages.

1.  However "#" is __not a valid Topic Name__ in our Grafana Data Source.  (Not sure why it fails)

    Hence we use __"all"__ as the substitute Topic Name for the "#" MQTT Topic.

## Receive MQTT Messages

__Incoming MQTT Messages__ are handled by this function: [pkg/mqtt/client.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/mqtt/client.go#L96-L148)

```go
//  Handle incoming MQTT messages
func (c *Client) HandleMessage(_ paho.Client, msg paho.Message) {
  //  Assume that the topic is "all". TODO: Support other topics.
  //  Previously: topic, ok := c.topics.Load(msg.Topic())
  topic, ok := c.topics.Load(defaultTopicName)
  if !ok {  //  Topic not found, quit
    return
  }

  //  Compose message
  message := Message{
    Timestamp: time.Now(),
    Value:     string(msg.Payload()),
  }
```

We begin by __composing a Message__ object that will be processed later.

Sorry again for this horrible hack: We reject messages without a __valid CBOR Base64 Payload__...

```go
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
```

Next we __store the Message__ object (keeping the most recent 1,000 messages)...

```go
  //  Store message for query
  topic.messages = append(topic.messages, message)

  //  Limit the size of the retained messages
  if len(topic.messages) > 1000 {
    topic.messages = topic.messages[1:]
  }

  //  Update the topic messages
  c.topics.Store(topic)
```

Then we __stream the message__ to a channel...

```go
  //  Stream message to topic "all". TODO: Support other topics.
  //  Previously: streamMessage := StreamMessage{Topic: msg.Topic(), Value: string(msg.Payload())}
  streamMessage := StreamMessage{Topic: defaultTopicName, Value: string(msg.Payload())}
  select {
  case c.stream <- streamMessage:
  default:
    //  Don't block if nothing is reading from the channel
  }
}
```

What happens next? Read on and find out...

# Transform MQTT Messages

Our Data Source calls this function to transform the Received MQTT Message into a __Grafana Data Frame__: [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L19-L44)

```go
//  Transform the array of MQTT Messages (JSON encoded) 
//  into a Grafana Data Frame.
func ToFrame(topic string, messages []mqtt.Message) *data.Frame {
  count := len(messages)
  if count > 0 {
    first := messages[0].Value

    //  JSON Message must begin with "{"
    if strings.HasPrefix(first, "{") {
      return jsonMessagesToFrame(topic, messages)
    }
  }
  //  Omitted: Handle non-JSON messages
```

The code above __forwards the received messages__ (JSON format) to this function: [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L46-L129)

```go
//  Transform the array of MQTT Messages (JSON encoded) 
//  into a Grafana Data Frame. See sample messages: https://github.com/lupyuen/the-things-network-datasource#mqtt-log
func jsonMessagesToFrame(topic string, messages []mqtt.Message) *data.Frame {
  //  Quit if no messages to transform
  count := len(messages)
  if count == 0 {
    return nil
  }

  //  Transform the first message
  msg := messages[0]

  //  Decode the CBOR payload
  body, err := decodeCborPayload(msg.Value)
  if err != nil {
    return set_error(data.NewFrame(topic), err)
  }
```

We begin by __decoding the CBOR payload__ for the first message.

(More about this in the next chapter)

Next we construct the __Timestamp Field__...

```go
  //  Construct the Timestamp field
  timeField := data.NewFieldFromFieldType(data.FieldTypeTime, count)
  timeField.Name = "Time"
  timeField.SetConcrete(0, msg.Timestamp)
```

We compose the __Data Fields__ (like "`t`" and "`l`") for the first message...

```go
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
```

(We'll see "`get_type`" in the next chapter)

Now we do the same for the __remaining messages__...

```go
  //  Transform the messages after the first one
  for row, m := range messages {
    //  Skip the first message
    if row == 0 {
      continue
    }

    //  Decode the CBOR payload
    body, err := decodeCborPayload(m.Value)
    if err != nil {  //  Ignore decode errors
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
```

Finally we __pack all the Data Fields__ into a Data Frame...

```go
  //  Construct the Data Frame
  frame := data.NewFrame(topic, timeField)

  //  Append the fields to the Data Frame
  for _, key := range keys {
    frame.Fields = append(frame.Fields, fields[key])
  }
  return frame
}
```

And we return the transformed Data Frame to Grafana.

Transformation Complete!

_How do we handle transformation errors?_

We call this function to __set the error__ on the Data Frame, and return it to Grafana: [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L231-L239)

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

> ![Transforming MQTT Messages](https://lupyuen.github.io/images/grafana-code.png)

# Decode CBOR Payload

We've seen the Message Transformation Logic, now we __decode the CBOR payload__ in the MQTT Message: [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L131-L190)

```go
//  Decode the CBOR payload in the JSON message.
//  See sample messages: https://github.com/lupyuen/the-things-network-datasource#mqtt-log
func decodeCborPayload(msg string) (map[string]interface{}, error) {
  //  Deserialise the message doc to a map of string → interface{}
  var doc map[string]interface{}
  err := json.Unmarshal([]byte(msg), &doc)
  if err != nil {
    return nil, err
  }
```

We start by __deserialising the JSON message__.

Remember that our __Message Payload__ is located at...

```text
uplink_message → frm_payload
```

We __extract the Message Payload__ like so...

```go
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
```

Message Payload is __encoded with Base64__, thus we decode it...

```go
  //  Base64 decode the Payload
  payload, err := base64.StdEncoding.DecodeString(frm_payload)
  if err != nil {
    return nil, err
  }
```

Next we __decode the CBOR payload__...

```go
  //  Decode CBOR payload to a map of String → interface{}
  var body map[string]interface{}
  err = cbor.Unmarshal(payload, &body)
  if err != nil {
    return nil, err
  }
```

(Yep we've seen this earlier)

To support filtering by Device ID, we __extract the Device ID__ from the MQTT Message...

```go
  //  Add the Device ID to the body: end_device_ids → device_id
  end_device_ids, ok := doc["end_device_ids"].(map[string]interface{})
  if ok {
    device_id, ok := end_device_ids["device_id"].(string)
    if ok {
      body["device_id"] = device_id
    }
  }
  return body, nil
}
```

Finally we return the decoded CBOR payload.

(Containing "`t`", "`l`" and the Device ID)

> ![Decoding the CBOR Payload](https://lupyuen.github.io/images/grafana-code2.png)

## Convert CBOR Type

Note that we need to specify the __types of Data Fields__ when populating a Grafana Data Frame.

We call this function to __map CBOR Types__ to Grafana Data Field Types: [pkg/plugin/message.go](https://github.com/lupyuen/the-things-network-datasource/blob/main/pkg/plugin/message.go#L192-L229)

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

  //  CBOR floating points decode to float64.
  case float64:
    return data.FieldTypeNullableFloat64

  //  CBOR text strings decode to string.
  case string:
    return data.FieldTypeNullableString
```

## Testing the Data Source

_Testing the MQTT Message Transformation looks painful!_

Indeed. That's why we wrote another Go program to test the transformation by calling __jsonMessagesToFrame__...

![Testing the MQTT Message Transformation](https://lupyuen.github.io/images/grafana-test.png)

# Troubleshooting

If we have problems with the Data Source, enabling __Debug Logging__ might help.

Edit the __Grafana Configuration File__...

```text
## For Linux:
/usr/share/grafana/conf/defaults.ini

## For macOS:
/usr/local/etc/grafana/grafana.ini

## For Windows:
C:\Program Files\GrafanaLabs\grafana\conf\defaults.ini
```

Set the __Log Level__...

```text
[log]
level = debug
```

Save the file and restart the Grafana Server.

Check the __Grafana Log__ at...

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

Today we have __streamed Sensor Data__ from The Things Network to Grafana over MQTT...

![Visualising The Things Network Sensor Data with Grafana](https://lupyuen.github.io/images/grafana-flow.jpg)

_Wait... We're streaming the Sensor Data without storing it?_

Yep this __streaming setup for Grafana__ requires fewer components because it doesn't store the data.

But this streaming setup has __limitations__...

1.  What happens when we __restart our Grafana Server__?

    All our Sensor Data is lost!

1.  We're remembering only the __last 1,000 messages__.

    Which is OK for checking real-time Sensor Data transmitted by our devices...

    But not OK for observing __Sensor Data trends over time__!

_Can we store the Sensor Data?_

We can store the Sensor Data in [__Prometheus__](https://prometheus.io/), the open source __Time-Series Data Store__...

![Storing The Things Network Sensor Data with Prometheus](https://lupyuen.github.io/images/grafana-flow2.jpg)

Grafana supports __Prometheus as a Data Source__, so pushing our Sensor Data from Prometheus to Grafana is easy.

To __ingest MQTT Messages__ from The Things Network into Prometheus, we need an
__MQTT Gateway__ like this...

-   [__hikhvar/mqtt2prometheus__](https://github.com/hikhvar/mqtt2prometheus)

This Grafana setup looks more complicated, but it works well for visualising historical Sensor Data.

# What's Next

I hope you enjoyed our exploration today: Streaming Sensor Data from The Things Network to Grafana over MQTT.

In the next article we shall head back to [__PineDio Stack BL604__](https://lupyuen.github.io/articles/ttn) and transmit actual Sensor Data to The Things Network, encoded with CBOR.

-   [__"Encode Sensor Data with CBOR on BL602"__](https://lupyuen.github.io/articles/cbor)

-   [__"Internal Temperature Sensor on BL602"__](https://lupyuen.github.io/articles/tsen)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss the article on Reddit](https://www.reddit.com/r/grafana/comments/pw9hnz/grafana_data_source_for_the_things_network/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/grafana.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/grafana.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1440459917828050946)

1.  What exactly are __"`t`"__ and __"`l`"__ in our Sensor Data?

    ```json
    { 
      "t": 1234, 
      "l": 2345 
    }
    ```

    "`t`" and "`l`" represent our (imaginary) __Temperature Sensor__ and __Light Sensor__.

    We __shortened the Field Names__ to fit the Sensor Data into 11 bytes of CBOR.

    With Grafana we can map "`t`" and "`l`" to their full names for display.
    
1.  Why is the temperature transmitted as an __integer__: `1234`?

    That's because __floating-point numbers compress poorly__ with CBOR unless we select the proper encoding.

    (Either 3 bytes, 5 bytes or 9 bytes per float. See the next note)

    Instead we assume that our integer data has been __scaled up 100 times__.

    (So `1234` actually means `12.34` ºC)

    We may configure Grafana to divide our integer data by 100 when rendering the values.

1.  If we're actually __encoding floats in CBOR__, how do we select the proper encoding?

    The CBOR spec says that there are [__3 ways to encode floats__](https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and-)...

    -   [IEEE 754 __Half-Precision__ Float (16 bits)](https://en.m.wikipedia.org/wiki/Half-precision_floating-point_format)

        (__3.3__ significant decimal digits)

    -   [IEEE 754 __Single-Precision__ Float (32 bits)](https://en.m.wikipedia.org/wiki/Single-precision_floating-point_format)

        (__6 to 9__ significant decimal digits)

    -   [IEEE 754 __Double-Precision__ Float (64 bits)](https://en.m.wikipedia.org/wiki/Double-precision_floating-point_format)

        (__15 to 17__ significant decimal digits)

    What would be the proper encoding for a float (like 12.34) that could range from 0.00 to 99.99?

    This means that we need __4 significant decimal digits__.

    Which is too many for a Half-Precision Float (16 bits), but OK for a __Single-Precision__ Float (32 bits).

    Thus we need __5 bytes__ to encode the float. (Including the CBOR Initial Byte)

    (Thanks to [__@chrysn__](https://chaos.social/@chrysn/107003343164025849) for highlighting this!)

1.  Is it meaningful to record temperatures that are accurate to 0.01 ºC?

    How much accuracy do we need for Sensor Data anyway?

    The accuracy for our Sensor Data depends on...

    1. Our monitoring requirements, and

    1. Accuracy of our sensors

    Learn more about Accuracy and Precision of Sensor Data...

    ["IoT’s Lesser Known Power: “Good Enough” Data Accuracy"](https://kotahi.net/iots-lesser-known-power-good-enough-data-accuracy/)

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
