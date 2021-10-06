# IoT Digital Twin with Roblox and The Things Network

📝 _12 Oct 2021_

[__Roblox__](https://developer.roblox.com/en-us/) is a __Multiplayer Virtual World__ that lets us create __3D Objects__ and interact with them. (Free to create and play)

[__The Things Network__](https://lupyuen.github.io/articles/ttn) is a __Public Wireless Network__ that connects many __IoT Gadgets__ around the world. (It's free too)

_Can we connect Roblox to The Things Network... To Monitor and Control Real-World Gadgets?_

![Digital Twin](https://lupyuen.github.io/images/digital-twin.jpg)

Think of the possibilities...

1.  Walk around a __Roblox House__ to __monitor the temperature__ in our Smart Home. 

    Flip the lights on and off in the Virtual House, to __control the lights__ in our Real Home.

    [(Check out this excellent article by Camden Bruce)](https://medium.com/@camden.o.b/how-we-could-make-a-roblox-smart-home-that-connects-to-the-real-world-e4d89b309516)

1.  Wander about a __Roblox Farm__ to check on __Farm Crops and Livestock__ in real life.

    [(Yes there are Cow Sensors)](https://www.thethingsindustries.com/news/implementing-gps-cattle-tracking-solution-lorawan/)

1.  Teach young learners about __Internet of Things (IoT)__...

    How __Sensors and Actuators__ work, and how they impact our lives.

Sounds very "Free Guy" and "Matrix"-ish, but the above is actually a well-known concept in IoT: __Digital Twin__.

_What's a Digital Twin?_

A [__Digital Twin__](https://en.m.wikipedia.org/wiki/Digital_twin) is a Virtual Object that __mirrors a Real-World Object__ through __Sensors and Actuators__. (Like the pic above)

For today's experiment we shall take this IoT Gadget: [__PineDio Stack BL604 RISC-V Board__](https://lupyuen.github.io/articles/pinedio)...

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

And turn it into a __Virtual Gadget in Roblox__ such that...

-  If our __Real Gadget__ feels hot...

-  Then our __Virtual Gadget__ looks hot too!

All __Roblox Scripts__ may be found in this repo...

-   [__lupyuen/roblox-the-things-network__](https://github.com/lupyuen/roblox-the-things-network)

(Apologies if my Roblox looks rough... This is my first time using Roblox 🙏)

![Cold / Hot / Normal IoT Objects rendered in Roblox](https://lupyuen.github.io/images/roblox-title.jpg)

# Roblox Mirrors Real Life

The pic shows what we shall accomplish with Roblox... 

A Virtual Object that __visualises the Live Temperature__ of our Real Object (PineDio Stack)

-   __Freezing Cold__ (left)

-   __Normal Temperature__ (middle)

    (Think Shrek and green fireflies)

-   __Fiery Hot__ (right)

In fact we'll show __10,000 Levels of Hotness / Coldness__, thanks to a little Math. [(And Linear Interpolation)](https://en.wikipedia.org/wiki/Linear_interpolation)

-   [__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=3CP7ELTAFLg)

_What magic makes this mirroring possible?_

This mirroring of real things in Roblox is possible because...

1.  Roblox lets us write __Lua Scripts__ that can make __HTTP Requests__ to the internet

1.  The Things Network exposes a __HTTP Service__ that lets us retrieve the __Sensor Data__ (like Temperature) sent by IoT Gadgets

Connect (1) to (2) and we'll get a Roblox Gadget that __mirrors the Hot / Cold State__ of a Real Gadget.

Let's talk about Roblox Lua Scripts and HTTP Requests...

[(More about Roblox Lua Scripting)](https://education.roblox.com/en-us/resources/intro-to-coding-coding-1-create-a-script)

[(More about The Things Network)](https://lupyuen.github.io/articles/ttn)

![Roblox talking to The Things Network](https://lupyuen.github.io/images/roblox-http.jpg)

# Roblox Fetches Sensor Data

Roblox provides a __HttpService API__ that we may call in our Lua Scripts to __fetch External HTTP URLs__ (via GET and POST)...

-   [__Roblox HttpService API__](https://developer.roblox.com/en-us/api-reference/class/HttpService)

Below we see HttpService in action, fetching the current __latitude and longitude of International Space Station__...

![Roblox Lua Script calls HttpService](https://lupyuen.github.io/images/roblox-script.png)

[(Source code at the bottom of this page)](https://developer.roblox.com/en-us/api-reference/class/HttpService)

To __fetch Sensor Data__ from The Things Network, we have created a __getSensorData__ function in [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L19-L71).

When we run this Roblox Script...

```lua
-- Fetch the Sensor Data from The Things Network (LoRa)
local sensorData = getSensorData()

-- Show the Temperature
if sensorData then
  print("Temperature:")
  print(sensorData.t)
else
  print("Failed to get sensor data")
end
```

We should see the __Temperature Sensor Data__ fetched from The Things Network...

```text
Temperature: 1236
```

(This means `12.36` ºC, our values have been scaled by 100)

Let's study the code inside our [__getSensorData__](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L19-L71) function.

## Define Constants

We begin by defining the constants for accessing The Things Network: [`DigitalTwin.lua`](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L1-L71)

```lua
-- TODO: Change this to your Application ID for The Things Network
-- (Must have permission to Read Application Traffic)
local TTN_APPLICATION_ID = "YOUR_APPLICATION_ID"

-- TODO: Change this to your API Key for The Things Network
local TTN_API_KEY = "YOUR_API_KEY"

-- TODO: Change this to your region-specific URL for The Things Network
local TTN_URL = "https://au1.cloud.thethings.network/api/v3/as/applications/" .. TTN_APPLICATION_ID .. "/packages/storage/uplink_message?limit=1&order=-received_at"
```

("`..`" in Lua means concatenate the strings)

Our URL for The Things Network (__TTN_URL__) looks like...

```uri
https://au1.cloud.thethings.network/api/v3/as/
  applications/YOUR_APPLICATION_ID/
  packages/storage/uplink_message
```

## Import Modules

Next we get the __HttpService__ from Roblox...

```lua
-- Get the HttpService for making HTTP Requests
local HttpService = game:GetService("HttpService")
```

__HTTP Requests must be enabled__ in Roblox...

Click Home → Game Settings → Security → Allow HTTP Requests

We import the __ModuleScripts__ that will be called to decode our Sensor Data...

```lua
-- Load the Base64 and CBOR ModuleScripts from ServerStorage
local ServerStorage = game:GetService("ServerStorage")
local base64 = require(ServerStorage.Base64)
local cbor   = require(ServerStorage.Cbor)
```

We'll talk about Base64 and CBOR in a while.

[(More about Roblox ModuleScripts)](https://education.roblox.com/en-us/resources/intro-to-module-scripts)

## Send HTTP Request

TODO

```lua
-- Fetch Sensor Data from The Things Network (LoRa) as a Lua Table
local function getSensorData()
  -- HTTPS JSON Response from The Things Network
  local response = nil
  -- Lua Table parsed from JSON response
  local data = nil
  -- Message Payload from the Lua Table (encoded with Base64)
  local frmPayload = nil
  -- Message Payload after Base64 Decoding
  local payload = nil
  -- Lua Table of Sensor Data after CBOR Decoding
  local sensorData = nil
```

TODO

```lua  
  -- Set the API Key in the HTTP Request Header	
  local headers = {
    ["Authorization"] = "Bearer " .. TTN_API_KEY,
  }
```

TODO

```lua
  -- Wrap with pcall in case something goes wrong
  pcall(function ()

    -- Fetch the data from The Things Network, no caching
    response = HttpService:GetAsync(TTN_URL, false, headers)
```

![JSON HTTP Response decoded as Lua Table](https://lupyuen.github.io/images/roblox-script2.png)

## Decode HTTP Response

TODO

```lua    
    -- Decode the JSON response into a Lua Table
    data = HttpService:JSONDecode(response)
```

TODO

```lua    
    -- Get the Message Payload. If missing, pcall will catch the error.
    frmPayload = data.result.uplink_message.frm_payload
```

TODO

```lua    
    -- Base64 Decode the Message Payload
    payload = base64.decode(frmPayload)

    -- Decode the CBOR Map to get Sensor Data
    sensorData = cbor.decode(payload)
  end)	
```

(More about Base64 and CBOR in a while)

## Check Errors

TODO

```lua  
  -- Show the error
  if response == nil then
    print("Error returned by The Things Network")
  elseif data == nil then
    print("Failed to parse JSON response from The Things Network")
  elseif frmPayload == nil then
    print("Missing message payload")
  elseif payload == nil then
    print("Base64 decoding failed")
  elseif sensorData == nil then
    print("CBOR decoding failed")
  end
```

## Return Sensor Data

TODO

```lua
  -- sensorData will be nil if our request failed or JSON failed to parse
  -- or Message Payload missing or Base64 / CBOR decoding failed
  return sensorData
end
```

# Roblox Mirroring In Action

TODO

Enable HTTP Requests: Click Home → Game Settings → Security → Allow HTTP Requests

Under `Workspace`, create a `Part`.

Under the `Part`, create a `Script`.

Copy and paste the script from [`DigitalTwin.lua`](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua)

Follow the steps in the next section to copy and paste the ModuleScripts for `Base64` and `Cbor`

# Decode Base64 and CBOR in Roblox

TODO

Under `ServerStorage`, create two __ModuleScripts__: `Base64` and `Cbor`.

Copy and paste the ModuleScripts from...

-   [`Base64`](https://github.com/lupyuen/roblox-the-things-network/blob/main/Base64.lua)

-   [`Cbor`](https://github.com/lupyuen/roblox-the-things-network/blob/main/Cbor.lua)

(Yep they need to be __ModuleScripts__. Normal Scripts won't work)

To test Base64 and CBOR Decoding...

```lua
-- Load the Base64 and CBOR ModuleScripts from ServerStorage
local ServerStorage = game:GetService("ServerStorage")
local base64 = require(ServerStorage.Base64)
local cbor = require(ServerStorage.Cbor)

-- Base64 Decode the Message Payload
payload = base64.decode('omF0GQTUYWwZCSs=')
print("payload:")
print(payload)

-- Decode the CBOR Map
sensorData = cbor.decode(payload)
print("sensorData:")
print(sensorData)
```

We should see...

```text
payload:
�at�al

sensorData:
{
  ["l"] = 2347,
  ["t"] = 1236
}
```

The ModuleScripts were copied from...

[iskolbin/lbase64](https://github.com/iskolbin/lbase64/blob/master/base64.lua)

[Zash/lua-cbor](https://github.com/Zash/lua-cbor/blob/master/cbor.lua)

This line in [base64.lua](https://github.com/iskolbin/lbase64/blob/master/base64.lua) was changed from...

```lua
local extract = _G.bit32 and _G.bit32.extract
```

To...

```lua
local extract = bit32 and bit32.extract
```

TODO7

![](https://lupyuen.github.io/images/roblox-script3.png)

TODO8

![](https://lupyuen.github.io/images/roblox-script4.png)

TODO9

![](https://lupyuen.github.io/images/roblox-script5.png)

# Render Temperature With Roblox Particle Emitter

TODO

Let's use a Roblox Particle Emitter to show the Temperature (t) of our object...

![Cold / Hot / Normal IoT Objects rendered in Roblox](https://lupyuen.github.io/images/roblox-title2.jpg)

We have defined 3 Particle Emitters: Cold (t=0), Normal (t=5000), Hot (t=10000).

To render the Temperature, we shall do Linear Interpolation of the 3 Particle Emitters...

```yaml
COLD Particle Emitter (t=0)
  Acceleration: 0, 0, 0
  Color: 0 0.333333 1 1 0 1 0.333333 1 1 0 
  Drag: 5
  EmissionDirection: Enum.NormalId.Top
  Lifetime: 5 10 
  LightEmission: 1
  LightInfluence: 1
  Orientation: Enum.ParticleOrientation.FacingCamera
  Rate: 20
  Rotation: 0 180 
  RotSpeed: -170 -170 
  Size: 0 1 0 1 1 0 
  Speed: 0 0 
  SpreadAngle: 10, 10
  Texture: rbxasset:textures/particles/sparkles_main.dds
  TimeScale: 1
  Transparency: 0 0 0 1 0 0 
  VelocityInheritance: 0
  ZOffset: 0

NORMAL Particle Emitter (t=5000)
  Acceleration: 0, 0, 0
  Color: 0 0.333333 0.666667 0 0 1 0.333333 0.666667 0 0 
  Drag: 10
  EmissionDirection: Enum.NormalId.Top
  Lifetime: 5 10 
  LightEmission: 0
  LightInfluence: 1
  Orientation: Enum.ParticleOrientation.FacingCamera
  Rate: 20
  Rotation: 0 0 
  RotSpeed: 0 0 
  Size: 0 0.2 0 1 0.2 0 
  Speed: 5 5 
  SpreadAngle: 50, 50
  Texture: rbxasset:textures/particles/sparkles_main.dds
  TimeScale: 1
  Transparency: 0 0 0 1 0 0 
  VelocityInheritance: 0
  ZOffset: 0

HOT Particle Emitter (t=10000)
  Acceleration: 0, 0, 0
  Color: 0 1 0.333333 0 0 1 1 0.333333 0 0 
  Drag: 0
  EmissionDirection: Enum.NormalId.Top
  Lifetime: 5 10 
  LightEmission: 0
  LightInfluence: 0
  Orientation: Enum.ParticleOrientation.FacingCamera
  Rate: 20
  Rotation: 0 0 
  RotSpeed: 0 0 
  Size: 0 0.4 0 1 0.4 0 
  Speed: 1 1 
  SpreadAngle: 50, 50
  Texture: rbxasset:textures/particles/sparkles_main.dds
  TimeScale: 1
  Transparency: 0 0 0 1 0 0 
  VelocityInheritance: 0
  ZOffset: 0
```

Values to be interpolated...

```yaml
Color:
  COLD:
    0 0.333333 1 1 0 
    1 0.333333 1 1 0 
  NORMAL:
    0 0.333333 0.666667 0 0 
    1 0.333333 0.666667 0 0 
  HOT:
    0 1 0.333333 0 0 
    1 1 0.333333 0 0 

Drag:
  COLD: 5
  NORMAL: 10
  HOT: 0

LightEmission: 
  COLD: 1
  NORMAL: 0
  HOT: 0

LightInfluence: 
  COLD: 1
  NORMAL: 1
  HOT: 0

Rotation: 
  COLD: 0 180 
  NORMAL: 0 0 
  HOT: 0 0 

RotSpeed: 
  COLD: -170 -170 
  NORMAL: 0 0 
  HOT: 0 0 

Size: 
  COLD: 0 1 0 1 1 0 
  NORMAL: 0 0.2 0 1 0.2 0 
  HOT: 0 0.4 0 1 0.4 0 
  
Speed: 
  COLD: 0 0 
  NORMAL: 5 5 
  HOT: 1 1 

SpreadAngle: 
  COLD: 10, 10
  NORMAL: 50, 50
  HOT: 50, 50
```

The properties of the Particle Emitters were dumped with the `dumpParticleEmitter` function in [`DigitalTwin.lua`](DigitalTwin.lua).

Note that `rbxasset` won't work for setting the Texture...

```lua
emitter.Texture = "rbxasset:textures/particles/sparkles_main.dds"
```

But `rbxassetid` works OK...

```lua
-- Texture for the particles: "star sparkle particle" by @Vupatu
-- https://www.roblox.com/library/6490035152/star-sparkle-particle
emitter.Texture = "rbxassetid://6490035152"
```

To create a Particle Emitter for Normal Temperature, we call `createParticleEmitter` in [`DigitalTwin.lua`](DigitalTwin.lua)

```lua
-- Create a Particle Emitter for Normal Temperature
local emitter = createParticleEmitter()
```

To interpolate the Particle Emitter for High / Mid / Low Temperatures, we call `updateParticleEmitter` in [`DigitalTwin.lua`](DigitalTwin.lua)

```lua
-- Gradually update the emitter for Temperature=10,000 to 0
updateParticleEmitter(emitter, T_MAX)
wait(5)
for t = T_MAX, T_MIN, -600 do
  print(string.format("t: %d", t))
  updateParticleEmitter(emitter, t)
  wait(4)
end
```

Here's how the Interpolating Particle Emitter looks...

-   [__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=3CP7ELTAFLg)

TODO2

![](https://lupyuen.github.io/images/roblox-emitter.png)

TODO4

![](https://lupyuen.github.io/images/roblox-interpolate.png)

TODO1

![](https://lupyuen.github.io/images/roblox-ar.jpg)

# What's Next

TODO

We shall head back and transmit BL602 / BL604's __Internal Temperature Sensor Data__ to The Things Network.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/roblox.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/roblox.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1443824711050301444)

# Appendix: Install Roblox Studio

TODO

Sign up for a free account at 

Login

Click "Create" in top bar

Click "Start Creating"

For macOS: Delete Roblox Studio under the __Applications Folder__. Reboot and reinstall.

For Linux: [See this](https://roblox.fandom.com/wiki/Tutorial:Using_Roblox_on_Linux)

# Appendix: Fetch Sensor Data from The Things Network

TODO

The Things Network exposes an API (HTTP GET) to fetch the Uplink Messages transmitted by our IoT Device...

[Retrieve Uplink Messages](https://www.thethingsindustries.com/docs/integrations/storage/retrieve/)

Here's the command to fetch the latest Uplink Message...

```bash
curl \
  -G "https://au1.cloud.thethings.network/api/v3/as/applications/$YOUR_APPLICATION_ID/packages/storage/uplink_message" \
  -H "Authorization: Bearer $YOUR_API_KEY" \
  -H "Accept: text/event-stream" \
  -d "limit=1" \
  -d "order=-received_at"
```

Which returns...

```json
{
  "result": {
    "end_device_ids": {
      "device_id": "eui-YOUR_DEVICE_EUI",
      "application_ids": {
        "application_id": "luppy-application"
      },
      "dev_eui": "YOUR_DEVICE_EUI",
      "dev_addr": "YOUR_DEVICE_ADDR"
    },
    "received_at": "2021-10-02T12:10:54.594006440Z",
    "uplink_message": {
      "f_port": 2,
      "f_cnt": 3,
      "frm_payload": "omF0GQTUYWwZCSs=",
      "rx_metadata": [
        {
          "gateway_ids": {
            "gateway_id": "luppy-wisgate-rak7248",
            "eui": "YOUR_GATEWAY_EUI"
          },
          "time": "2021-10-02T13:04:34.552513Z",
          "timestamp": 3576406949,
          "rssi": -53,
          "channel_rssi": -53,
          "snr": 12.2,
          "location": {
            "latitude": 1.27125,
            "longitude": 103.80795,
            "altitude": 70,
            "source": "SOURCE_REGISTRY"
          },
          "channel_index": 4
        }
      ],
      "settings": {
        "data_rate": {
          "lora": {
            "bandwidth": 125000,
            "spreading_factor": 10
          }
        },
        "data_rate_index": 2,
        "coding_rate": "4/5",
        "frequency": "922600000",
        "timestamp": 3576406949,
        "time": "2021-10-02T13:04:34.552513Z"
      },
      "received_at": "2021-10-02T12:10:54.385972437Z",
      "consumed_airtime": "0.370688s",
      "network_ids": {
        "net_id": "000013",
        "tenant_id": "ttn",
        "cluster_id": "ttn-au1"
      }
    }
  }
}
```

`result.uplink_message.frm_payload` contains the Sensor Data that we need, encoded with Base64 and CBOR...

```json
"frm_payload": "omF0GQTUYWwZCSs="
```

Our Sensor Data is encoded with [CBOR](https://en.wikipedia.org/wiki/CBOR) to keep the LoRa Packets small (max 12 bytes), due to the Fair Use Policy of The Things Network...

-   ["Fair Use of The Things Network"](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

More about CBOR Encoding...

-   ["Encode Sensor Data with CBOR on BL602"](https://lupyuen.github.io/articles/cbor)

TODO10

![](https://lupyuen.github.io/images/roblox-ttn.jpg)

