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

[(Source)](https://developer.roblox.com/en-us/api-reference/function/HttpService/GetAsync)

To __fetch Sensor Data__ from The Things Network, we have created a __getSensorData__ function in [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L19-L74).

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

[(Source)](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L326-L333)

We should see the __Temperature Sensor Data__ fetched from The Things Network...

```text
Temperature: 1236
```

(This means `12.36` ºC, our values have been scaled up by 100 times)

Let's study the code inside our [__getSensorData__](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L19-L74) function.

## Define Constants

We begin by __defining the constants__ for accessing The Things Network: [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L1-L74)

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

(More about these settings in the Appendix)

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

Our function begins by __declaring the variables__...

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

-   __response__: Contains the HTTP Response (JSON format) returned by The Things Network

-   __data__: Lua Table we get after parsing the JSON HTTP Response

-   __frmPayload__: Encoded Sensor Data, extracted from our Parsed JSON Response

-   __payload__: Sensor Data after Base64 Decoding

-   __sensorData__: Sensor Data after CBOR Decoding

We set the __API Key__ in the HTTP Request Header (as "Authorization")...

```lua  
  -- Set the API Key in the HTTP Request Header	
  local headers = {
    ["Authorization"] = "Bearer " .. TTN_API_KEY,
  }
```

("`..`" in Lua means concatenate the strings)

Then we __fetch the URL__ (via HTTP GET), passing the API Key in the headers...

```lua
  -- Wrap with pcall in case something goes wrong
  pcall(function ()

    -- Fetch the data from The Things Network, no caching
    response = HttpService:GetAsync(TTN_URL, false, headers)
```

[(GetAsync is documented here)](https://developer.roblox.com/en-us/api-reference/function/HttpService/GetAsync)

_What is "pcall"?_

We wrap our code with __"pcall"__ to catch any errors returned by the HTTP Fetching. 

(Also for catching Decoding Errors)

If any error occurs, execution resumes __after the "pcall" block__.

And we'll check for errors then.

[(pcall is documented here)](https://developer.roblox.com/en-us/api-reference/lua-docs/Lua-Globals)

![JSON HTTP Response decoded as Lua Table](https://lupyuen.github.io/images/roblox-script2.png)

## Decode HTTP Response

Now we __decode the HTTP Response__ (JSON format) from The Things Network.

First we __parse the JSON__ returned by The Things Network...

```lua    
    -- Decode the JSON response into a Lua Table
    data = HttpService:JSONDecode(response)
```

[(JSONDecode is documented here)](https://developer.roblox.com/en-us/api-reference/function/HttpService/JSONDecode)

This returns a __Lua Table__ that contains the JSON Fields.

(See the pic above)

As shown in the pic, we need to __extract the Encoded Sensor Data__ from the field: __result → uplink_message → frm_payload__

```lua    
    -- Get the Message Payload. If missing, pcall will catch the error.
    frmPayload = data.result.uplink_message.frm_payload
```

__frmPayload__ contains the Sensor Data encoded with Base64 and CBOR.

(Looks like gibberish: "`omF0GQTUYWwZCSs=`")

We call the Base64 and CBOR ModuleScripts to __decode the Sensor Data__...

```lua    
    -- Base64 Decode the Message Payload
    payload = base64.decode(frmPayload)

    -- Decode the CBOR Map to get Sensor Data
    sensorData = cbor.decode(payload)

  -- End of pcall block
  end)
```

(More about Base64 and CBOR in a while)

__sensorData__ now contains meaningful Sensor Data in a Lua Table...

```lua
{
  ["l"] = 2347,
  ["t"] = 1236
}
```

Above are the values recorded by our __Light Sensor__ and __Temperature Sensor__, scaled up by 100 times.

Note that our __"pcall" block__ ends here. So we check the errors next.

## Check Errors

We're at the spot after the "pcall" block.

We __check for errors__ that could have occurred inside the "pcall" block...

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

This code checks for HTTP Request Errors and Decoding Errors.

## Return Sensor Data

Finally we __return the Sensor Data__ (as a Lua Table) to the caller...

```lua
  -- sensorData will be nil if our request failed or JSON failed to parse
  -- or Message Payload missing or Base64 / CBOR decoding failed
  return sensorData
end
```

Our Sensor Data is returned as __nil__ in case of error.

And that's how our Roblox Script fetches Sensor Data from The Things Network!

![Roblox Fetches Sensor Data](https://lupyuen.github.io/images/roblox-script3.png)

# Roblox Mirroring In Action

Before heading deeper into our Roblox Scripts, let's watch our __Virtual Gadget in action__!

1.  Download and install __Roblox Studio__...

    [__"Install Roblox Studio"__](https://lupyuen.github.io/articles/roblox#appendix-install-roblox-studio)

1.  In Roblox Studio, click __New → Classic Baseplate__

1.  We need to enable HTTP Requests...

    At the top bar, click __Home → Game Settings → Security → Allow HTTP Requests__

![Create Part in Roblox Studio](https://lupyuen.github.io/images/roblox-studio.png)

## Create Part and Script

1.  At __Explorer → Workspace__ (at right)...

    Click __(+)__ and create a __Part__

    (See pic above)

1.  Under our __Part__...

    Click __(+)__ and create a __Script__

    (See pic below)

1.  Copy and paste the contents of this link into the script...

    -   [__DigitalTwin.lua__](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua)

![Create Script in Roblox Studio](https://lupyuen.github.io/images/roblox-studio2.png)

## Edit Settings

1.  If we have an IoT Gadget connected to The Things Network: 

    Edit these settings...

    ```lua
    -- TODO: Change this to your Application ID for The Things Network
    -- (Must have permission to Read Application Traffic)
    local TTN_APPLICATION_ID = "YOUR_APPLICATION_ID"

    -- TODO: Change this to your API Key for The Things Network
    local TTN_API_KEY = "YOUR_API_KEY"

    -- TODO: Change this to your region-specific URL for The Things Network
    local TTN_URL = "https://au1.cloud.thethings.network/api/v3/as/applications/" .. TTN_APPLICATION_ID .. "/packages/storage/uplink_message?limit=1&order=-received_at"
    ```

    (More about this in the Appendix)

1.  If we don't have an IoT Gadget: 

    Leave the above settings as is. 

    The script will run in __Demo Mode__, simulating a real gadget.

![Create Base64 ModuleScript in Roblox Studio](https://lupyuen.github.io/images/roblox-studio3.png)

## Create ModuleScripts

1.  At __Explorer → ServerStorage__ (at right)...

    Click __(+)__ and create two __ModuleScripts__: 
    
    __`Base64`__ and __`Cbor`__

    (See pic above)

1.  Copy and paste the the contents of these links into the ModuleScripts...

    -   [__`Base64`__](https://github.com/lupyuen/roblox-the-things-network/blob/main/Base64.lua) (See pic above)

    -   [__`Cbor`__](https://github.com/lupyuen/roblox-the-things-network/blob/main/Cbor.lua) (See pic below)

    (Yep they need to be __ModuleScripts__. Normal Scripts won't work)

![Create Cbor ModuleScript in Roblox Studio](https://lupyuen.github.io/images/roblox-studio4.png)

## Watch It Run

At the top bar, click __Home → Play__

(Or press __F5__)

Roblox renders our Virtual Gadget in its __Hot / Cold State__!

[__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=3CP7ELTAFLg)

![Cold / Hot / Normal IoT Objects rendered in Roblox](https://lupyuen.github.io/images/roblox-title2.jpg)

# Decode Base64 and CBOR in Roblox

_Why do we need CBOR Decoding?_

Normally IoT Gadgets will transmit __Sensor Data in JSON__ like so....

```json
{ 
  "t": 1236, 
  "l": 2347 
}
```

That's __19 bytes of JSON__ for Temperature Sensor and Light Sensor Data.

But this won't fit into the __Maximum Message Size__ for The Things Network: __12 bytes__.

[(Assuming 10 messages per hour)](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

Instead we compress the Sensor Data into [__Concise Binary Object Representation (CBOR)__](https://en.wikipedia.org/wiki/CBOR) Format.

(CBOR works like a compact, binary form of JSON)

And we need only __11 bytes of CBOR!__

```text
a2 61 74 19 04 d4 61 6c 19 09 2b
```

[(More about CBOR)](https://lupyuen.github.io/articles/cbor)

![Encoding Sensor Data with CBOR on BL602](https://lupyuen.github.io/images/cbor-title.jpg)

[(Source)](https://lupyuen.github.io/articles/cbor)

_What about the Base64 Decoding?_

Our IoT Gadget transmits Sensor Data to The Things Network in __Binary Format (CBOR)__.

But our Roblox script fetches the Sensor Data in __JSON Format__, which can't embed Binary Data.

Hence our Binary Data is converted to Text Format with [__Base64 Encoding__](https://en.wikipedia.org/wiki/Base64), when fetched by Roblox.

Our Sensor Data __encoded with CBOR__...

```text
a2 61 74 19 04 d4 61 6c 19 09 2b
```

Becomes this Text String when __encoded with Base64__...

```text
omF0GQTUYWwZCSs=
```

This explains why we need two stages of decoding: __Base64 followed by CBOR__.

![Create Base64 ModuleScript in Roblox Studio](https://lupyuen.github.io/images/roblox-studio3.png)

## Base64 and CBOR ModuleScripts

_How do we decode Base64 and CBOR in Roblox?_

We call these two __ModuleScripts in ServerStorage__...

-   [__`Base64`__](https://github.com/lupyuen/roblox-the-things-network/blob/main/Base64.lua)

-   [__`Cbor`__](https://github.com/lupyuen/roblox-the-things-network/blob/main/Cbor.lua)

Like so...

```lua
-- Load the Base64 and CBOR ModuleScripts from ServerStorage
local ServerStorage = game:GetService("ServerStorage")
local base64 = require(ServerStorage.Base64)
local cbor   = require(ServerStorage.Cbor)

-- Base64 Decode the Message Payload
payload = base64.decode('omF0GQTUYWwZCSs=')
print("payload:")
print(payload)

-- Decode the CBOR Map
sensorData = cbor.decode(payload)
print("sensorData:")
print(sensorData)
```

[(Source)](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L335-L343)

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

_Did we create the ModuleScripts from scratch?_

Nope, they were copied from __existing Lua Libraries__...

-   [__iskolbin/lbase64__](https://github.com/iskolbin/lbase64/blob/master/base64.lua)

-   [__Zash/lua-cbor__](https://github.com/Zash/lua-cbor/blob/master/cbor.lua)

_Was it difficult to port the Lua Libraries into Roblox?_

Not at all! We changed only one line of code in [__Base64.lua__](https://github.com/lupyuen/roblox-the-things-network/blob/main/Base64.lua#L28-L29) from...

```lua
local extract = _G.bit32 and _G.bit32.extract
```

To...

```lua
local extract = bit32 and bit32.extract
```

And the ModuleScripts worked perfectly!

![Porting Lua Libraries into Roblox](https://lupyuen.github.io/images/roblox-script5.png)

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

The properties of the Particle Emitters were dumped with the `dumpParticleEmitter` function in [__DigitalTwin.lua__](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua).

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

To create a Particle Emitter for Normal Temperature, we call `createParticleEmitter` in [__DigitalTwin.lua__](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua)

```lua
-- Create a Particle Emitter for Normal Temperature
local emitter = createParticleEmitter()
```

To interpolate the Particle Emitter for High / Mid / Low Temperatures, we call `updateParticleEmitter` in [__DigitalTwin.lua__](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua)

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

TODO

![](https://lupyuen.github.io/images/roblox-studio5.png)

TODO

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

Here are the steps to download and install __Roblox Studio for macOS and Windows__...

1.  Sign up for a free account at [__roblox.com__](https://www.roblox.com/home)

1.  Log in to [__roblox.com__](https://www.roblox.com/home)

1.  Click __"Create"__ at the top bar

1.  Click __"Start Creating"__

1.  The Roblox Studio Installer will be downloaded.

    Click the Installer to install Roblox Studio.

1.  __For macOS:__ If the Installer fails...

    Delete Roblox Studio in the __Applications Folder__.
    
    Reboot and reinstall Roblox Studio.

    (That's how I fixed Roblox Studio on macOS)

To install __Roblox Studio on Linux__, see this...

-   [__"Using Roblox on Linux"__](https://roblox.fandom.com/wiki/Tutorial:Using_Roblox_on_Linux)

If we're in China, Roblox works a little differently. See this...

-   [__"Roblox China"__](https://roblox.fandom.com/wiki/Roblox_China)

# Appendix: The Things Network Settings

TODO

-  [__The Things Network: Storage Integration__](https://www.thethingsindustries.com/docs/integrations/storage/)

Stores messages for roughly 2 or 3 days.

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

TODO

![](https://lupyuen.github.io/images/roblox-ttn2.png)

TODO

![](https://lupyuen.github.io/images/roblox-ttn3.png)

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
