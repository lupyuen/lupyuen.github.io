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
  ?limit=1&order=-received_at
```

[(More about these settings in the Appendix)](https://lupyuen.github.io/articles/roblox#appendix-the-things-network-settings)

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

    [(More about this in the Appendix)](https://lupyuen.github.io/articles/roblox#appendix-the-things-network-settings)

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

_How did we render the Temperature of our Roblox Gadget?_

_(The green fireflies thingy?)_

We rendered the Temperature with a [__Roblox Particle Emitter__](https://developer.roblox.com/en-us/articles/Particle-Emitters).

This is how we render a Particle Emitter in our Roblox Script...

```lua
-- Create a Particle Emitter for Normal Temperature
local emitter = createParticleEmitter()
```

[(Source)](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L285-L286)

The code above renders our Roblox Gadget with __Normal Temperature__.

(Yep Shrek and his green fireflies)

__createParticleEmitter__ is defined in [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L76-L133)...

```lua
-- Create the Particle Emitter for Normal Temperature
-- Based on https://developer.roblox.com/en-us/api-reference/class/ParticleEmitter
local function createParticleEmitter()

  -- Create an instance of Particle Emitter and enable it
  local emitter = Instance.new("ParticleEmitter")
  emitter.Enabled = true 
```

We begin by __creating an Instance__ of Particle Emitter.

Next we set the __rate of particles emitted__ and their lifetime...

```lua
  -- Number of particles = Rate * Lifetime
  emitter.Rate = 20 -- Particles per second
  emitter.Lifetime = NumberRange.new(5, 10) -- How long the particles should be alive (min, max)
```

(Why these Magic Numbers? We'll learn later)

We set the __texture of the particles__ to a Star Sparkle image...

```lua
  -- Visual properties
  -- Texture for the particles: "star sparkle particle" by @Vupatu
  -- https://www.roblox.com/library/6490035152/star-sparkle-particle
  emitter.Texture = "rbxassetid://6490035152"
```

(Somehow I couldn't set the texture to "rbxasset:textures/particles/sparkles_main.dds". Only "rbxassetid" works)

Our particles can __change color__, but we'll stick to green _(R=0.3, G=0.6, B=0.0)_...

```lua
  -- For Color, build a ColorSequence using ColorSequenceKeypoint
  local colorKeypoints = {
    -- API: ColorSequenceKeypoint.new(time, color)
    ColorSequenceKeypoint.new( 0.0, Color3.new(0.3, 0.6, 0.0)),  -- At time=0: Green
    ColorSequenceKeypoint.new( 1.0, Color3.new(0.3, 0.6, 0.0))   -- At time=1: Green
  }
  emitter.Color = ColorSequence.new(colorKeypoints)
```

This __Color Sequence__ says that from start _(time=0)_ to end _(time=1)_, the particles stay green.

We won't vary the __particle transparency__ either...

```lua
  -- For Transparency, build a NumberSequence using NumberSequenceKeypoint
  local numberKeypoints = {
    -- API: NumberSequenceKeypoint.new(time, size, envelop)
    NumberSequenceKeypoint.new( 0.0, 0.0);    -- At time=0, fully opaque
    NumberSequenceKeypoint.new( 1.0, 0.0);    -- At time=1, fully opaque
  }
  emitter.Transparency = NumberSequence.new(numberKeypoints)
```

From start to end, our particles are fully opaque.

We set the __Light Emission and Influence__...

```lua
  -- Light Emission and Influence
  emitter.LightEmission = 0 -- If 1: When particles overlap, multiply their color to be brighter
  emitter.LightInfluence = 1 -- If 0: Don't be affected by world lighting
```

We define the __speed and spread__ of our particles...

```lua
  -- Speed properties
  emitter.EmissionDirection = Enum.NormalId.Top -- Emit towards top
  emitter.Speed = NumberRange.new(5.0, 5.0) -- Speed
  emitter.Drag = 10.0 -- Apply drag to particle motion
  emitter.VelocitySpread = NumberRange.new(0.0, 0.0)
  emitter.VelocityInheritance = 0 -- Don't inherit parent velocity
  emitter.Acceleration = Vector3.new(0.0, 0.0, 0.0)
  emitter.LockedToPart = false -- Don't lock the particles to the parent 
  emitter.SpreadAngle = Vector2.new(50.0, 50.0) -- Spread angle on X and Y
```

We set the __size and rotation__ of our particles...

```lua
  -- Simulation properties
  local numberKeypoints2 = {
    NumberSequenceKeypoint.new(0.0, 0.2);  -- Size at time=0
    NumberSequenceKeypoint.new(1.0, 0.2);  -- Size at time=1
  }
  emitter.Size = NumberSequence.new(numberKeypoints2)
  emitter.ZOffset = 0.0 -- Render in front or behind the actual position
  emitter.Rotation = NumberRange.new(0.0, 0.0) -- Rotation
  emitter.RotSpeed = NumberRange.new(0.0) -- Do not rotate during simulation
```

Finally we __add the emitter__ to our Roblox Part...

```lua  
  -- Add the emitter to our Part
  emitter.Parent = script.Parent
  return emitter
end
```

And our Roblox Gadget starts emitting green particles to represent Normal Temperature!

(Centre one in the pic below)

![Cold / Hot / Normal IoT Objects rendered in Roblox](https://lupyuen.github.io/images/roblox-title2.jpg)

## Magic Numbers

_All the Magic Numbers above... Where did they come from?_

I created __three Particle Emitters__ for the Cold, Normal and Hot Temperatures...

![Particle Emitters for Cold / Normal / Hot Temperatures](https://lupyuen.github.io/images/roblox-studio5.png)

I tweaked them till they looked OK. Then I __dumped the settings__ of the Particle Emitters like so...

```lua
-- Dump the 3 Particle Emitters: Cold, Normal, Hot
print("COLD Particle Emitter (t=0)")
dumpParticleEmitter(script.Parent.Cold)

print("NORMAL Particle Emitter (t=5000)")
dumpParticleEmitter(script.Parent.Normal)

print("HOT Particle Emitter (t=10000)")
dumpParticleEmitter(script.Parent.Hot)
```

[(Source)](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L345-L351)

(__dumpParticleEmitter__ is defined in [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L241-L262))

The __Particle Emitter settings__ look like...

```yaml
NORMAL Particle Emitter (t=5000)
  Acceleration: 0, 0, 0
  Color: 
    0 0.3 0.6 0 0 
    1 0.3 0.6 0 0 
  Drag: 10
  ...
```

[(See the complete settings)](https://lupyuen.github.io/articles/roblox#appendix-particle-emitter-settings)

These are the Magic Numbers that we plugged into our [__createParticleEmitter__](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L76-L133) function.

_Why did we create the Particle Emitter in Roblox Script?_

_Why not reuse the Particle Emitters that we have created manually?_

That's because we want to render __10,000 Levels of Hotness / Coldness__.

Our Roblox Script will __tweak the Particle Emitter at runtime__ to render the Live Temperature.

Read on to learn how we do this with [__Linear Interpolation__](https://en.wikipedia.org/wiki/Linear_interpolation).

![Cold / Hot / Normal IoT Objects rendered in Roblox](https://lupyuen.github.io/images/roblox-title2.jpg)

## Interpolate the Particle Emitter

Previously we have __dumped the settings__ for our Hot / Normal / Cold Particle Emitters...

```yaml
COLD Particle Emitter (t=0)
  Drag:  5
  Speed: 0 0 
  Color: (time, red, green, blue)
    0 0.3 1.0 1.0 
    1 0.3 1.0 1.0 
    ...

NORMAL Particle Emitter (t=5000)
  Drag:  10
  Speed: 5 5 
  Color: (time, red, green, blue)
    0 0.3 0.6 0.0 
    1 0.3 0.6 0.0 
    ...

HOT Particle Emitter (t=10000)
  Drag:  0
  Speed: 1 1 
  Color: (time, red, green, blue)
    0 1.0 0.3 0.0 
    1 1.0 0.3 0.0 
    ...
```

[(See the complete settings)](https://lupyuen.github.io/articles/roblox#appendix-particle-emitter-settings)

The three emitters represent the __Min / Mid / Max Temperatures__...

-   __Cold:__ `t=0`
-   __Normal:__ `t=5000`
-   __Hot:__ `t=10000`

_How shall we interpolate the three emitters... To render 10,000 Levels of Hotness / Coldness?_

Based on the values above, we derive the following values that shall be __interpolated into 10,000 levels__ as we transition between Cold / Normal / Hot...

```yaml
Drag:
  COLD:   5
  NORMAL: 10
  HOT:    0

Speed: 
  COLD:   0 0 
  NORMAL: 5 5 
  HOT:    1 1 

Color: (time, red, green, blue)
  COLD:
    0 0.3 1.0 1.0 
    1 0.3 1.0 1.0 
  NORMAL:
    0 0.3 0.6 0.0 
    1 0.3 0.6 0.0 
  HOT:
    0 1.0 0.3 0.0 
    1 1.0 0.3 0.0 
    ...
```

[(See the complete interpolation)](https://lupyuen.github.io/articles/roblox#appendix-particle-emitter-settings)

Let's plug the derived values into our Roblox Script.

![Interpolating the Particle Emitter](https://lupyuen.github.io/images/roblox-interpolate.png)

## Update the Particle Emitter

We take the values derived above and plug them into our __updateParticleEmitter__ function from [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L164-L239)...

```lua
-- Update the Particle Emitter based on the Temperature t.
-- t ranges from T_MIN (0) to T_MAX (10,000).
local function updateParticleEmitter(emitter, t)

  -- Interpolate Drag:
  -- COLD:   5
  -- NORMAL: 10
  -- HOT:    0
  emitter.Drag = lin(t, 5.0, 10.0, 0.0)

  -- Interpolate Speed: 
  -- COLD:   0 0
  -- NORMAL: 5 5
  -- HOT:    1 1
  local speed = lin(t, 0.0, 5.0, 1.0)
  emitter.Speed = NumberRange.new(speed, speed) -- Speed
```

__lin__ is our helper function that computes [__Linear Interpolation__](https://en.wikipedia.org/wiki/Linear_interpolation).

(More about this in the next section)

In the code above we __interpolate the Drag and Speed__ of our Particle Emitter, based on the Temperature (t).

For the color of our Particle Emitter, we compute the __interpolated color__...

```lua
  -- Interpolate Color: (Red, Green, Blue)
  -- COLD:   0.3, 1.0, 1.0
  -- NORMAL: 0.3, 0.6, 0.0
  -- HOT:    1.0, 0.3, 0.0
  local color = Color3.new(
    lin(t, 0.3, 0.3, 1.0),  -- Red
    lin(t, 1.0, 0.6, 0.3),  -- Green
    lin(t, 1.0, 0.0, 0.0)   -- Blue
  )
```

Then we update the __Color Sequence__ based on the interpolated color...

```lua
  local colorKeypoints = {
    -- API: ColorSequenceKeypoint.new(time, color)
    ColorSequenceKeypoint.new(0.0, color),  -- At time=0
    ColorSequenceKeypoint.new(1.0, color)   -- At time=1
  }
  emitter.Color = ColorSequence.new(colorKeypoints)
```

[(See the rest of the function here)](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L164-L239)

And we're done! To render the Live Temperature, we call __updateParticleEmitter__ like so...

```lua
-- Create a Particle Emitter for Normal Temperature
local emitter = createParticleEmitter()

-- Update the emitter to render Temperature=1234
updateParticleEmitter(emitter, 1234)
```

[(Source)](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L282-L321)

Here's how our Interpolating Particle Emitter looks...

-   [__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=3CP7ELTAFLg)

![Updating the Particle Emitter](https://lupyuen.github.io/images/roblox-emitter.png)

## Linear Interpolation

_How does the __lin__ function compute Linear Interpolation?_

Earlier we saw this...

```lua
-- Interpolate Drag:
-- COLD:   5
-- NORMAL: 10
-- HOT:    0
emitter.Drag = lin(t, 5.0, 10.0, 0.0)
```

This code __interpolates the Drag__ of our Particle Emitter based on the Temperature (t).

The values passed to __lin__...

```text
5.0, 10.0, 0.0
```

Correspond to the Drag values for __Min / Mid / Max Temperatures__.

The Min / Mid / Max Temperatures are defined here: [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L135-L162)

```lua
-- Minimum, Maximum and Mid values for Temperature (t) that will be interpolated
local T_MIN = 0
local T_MAX = 10000
local T_MID = (T_MIN + T_MAX) / 2
```

We compute the [__Linear Interpolation__](https://en.wikipedia.org/wiki/Linear_interpolation) by drawing lines between the Min, Mid and Max values...

> ![Computing the Linear Interpolation](https://lupyuen.github.io/images/roblox-interpolate2.jpg)

Note that we compute the Linear Interpolation a little differently depending on whether the Temperature is __less or greater than 5,000__ (T_MID)...

> ![Computing the Linear Interpolation](https://lupyuen.github.io/images/roblox-interpolate3.jpg)

Below is our __lin__ function that handles both cases: [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L135-L162)

```lua
-- Linear Interpolate the value of y, given that
-- (1) x ranges from T_MIN to T_MAX
-- (2) When x=T_MIN, y=yMin
-- (3) When x=T_MID, y=yMid
-- (4) When x=T_MAX, y=yMax
local function lin(x, yMin, yMid, yMax)
  local y
  if x < T_MID then
    -- Interpolate between T_MIN and T_MID
    y = yMin + (yMid - yMin) * (x - T_MIN) / (T_MID - T_MIN)
  else
    -- Interpolate between T_MID and T_MAX
    y = yMid + (yMax - yMid) * (x - T_MID) / (T_MAX - T_MID)
  end	
  -- Force y to be between yMin, yMid and yMax
  if y < math.min(yMin, yMid, yMax) then
    y = math.min(yMin, yMid, yMax)
  end
  if y > math.max(yMin, yMid, yMax) then
    y = math.max(yMin, yMid, yMax)
  end
  return y
end
```

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

# Digital Twin Demo

As promised, here's the Real-Life Demo of our __Roblox Digital Twin__ featuring __PineDio Stack__! (Pic above)

-   [__Watch the Demo Video on YouTube__](https://youtu.be/QKjtue_tPGM)

We follow the instructions below to run the __LoRaWAN Firmware__ on PineDio Stack...

-   [__"Build and Run LoRaWAN Firmware"__](https://lupyuen.github.io/articles/cbor#appendix-build-and-run-lorawan-firmware)

![Digital Twin 55.55 ⁰C](https://lupyuen.github.io/images/roblox-demo.png)

Our demo setup...

-   __At Left__: Serial Terminal connected to our [__PineDio Stack board__](https://lupyuen.github.io/articles/pinedio)

    (We control PineDio Stack by entering commands into the Serial Terminal)

-   __At Right__: Roblox running our [__Digital Twin Script__](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua)

    (With __[Base64](https://github.com/lupyuen/roblox-the-things-network/blob/main/Base64.lua)__ and __[Cbor](https://github.com/lupyuen/roblox-the-things-network/blob/main/Cbor.lua)__ ModuleScripts)

-   Grey block is the __Roblox Gadget__ that mirrors our real-world IoT Gadget (PineDio Stack)...

    When __PineDio Stack__ gets hot, the __Roblox Gadget__ will look hot too!

-   We sync PineDio Stack (left) with Roblox Gadget (right) via [__The Things Network__](https://lupyuen.github.io/articles/ttn), the public wireless IoT network

-   Through The Things Network, Roblox fetches the __Live Temperature__ of PineDio Stack every 5 seconds.

    (Shown at lower right: `5555`)

The temperature is now __55.55 ⁰C__. Let's set the PineDio Stack temperature to __99.99 ⁰C__...

```bash
las_app_tx_cbor 2 0 9999 0
```

Our Roblox Gadget __receives the high temperature__ and bursts into flames!

![Digital Twin at 99.99 ⁰C](https://lupyuen.github.io/images/roblox-demo2.png)

Let's turn down PineDio Stack to __77.77 ⁰C__...

```bash
las_app_tx_cbor 2 0 7777 0
```

Our Roblox Gadget __receives the updated temperature__ over The Things Network. And cools down a little.

![Digital Twin at 77.77 ⁰C](https://lupyuen.github.io/images/roblox-demo3.png)

We cool PineDio Stack down to __33.33 ⁰C__...

```bash
las_app_tx_cbor 2 0 3333 0
```

Our Roblox Gadget __turns blue__.

![Digital Twin at 33.33 ⁰C](https://lupyuen.github.io/images/roblox-demo4.png)

We start to freeze PineDio Stack at __11.11 ⁰C__...

```bash
las_app_tx_cbor 2 0 1111 0
```

Our Roblox Gadget __turns into ice__!

![Digital Twin at 11.11 ⁰C](https://lupyuen.github.io/images/roblox-demo5.png)

## Demo Code

Below is the __source code for the demo__ that we've seen. It calls all the functions that we've covered in this article: [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L282-L324)

```lua
-- Main Function. Fetch and render the Sensor Data from The Things Network every 5 seconds.
-- If fetch failed, show Demo Mode.
local function main()	
  -- Create a Particle Emitter for Normal Temperature
  local emitter = createParticleEmitter()
  
  -- Loop forever fetching and rendering Sensor Data from The Things Network
  while true do
    -- Lua Table that will contain Sensor Data from The Things Network	
    local sensorData = nil

    -- Temperature from The Things Network. Ranges from 0 to 10,000.
    local t = nil

    -- If API Key for The Things Network is defined...
    if TTN_API_KEY ~= "YOUR_API_KEY" then
      -- Fetch the Sensor Data from The Things Network
      sensorData = getSensorData()	

      -- Get the Temperature if it exists
      if sensorData then
        t = sensorData.t
      end
    end

    -- If Temperature was successfully fetched from The Things Network...
    if t then
      -- Render the Temperature with our Particle Emitter
      print("t:", t)
      updateParticleEmitter(emitter, t)
    else
      -- Else render our Particle Emitter in Demo Mode
      print("Failed to get sensor data. Enter Demo Mode.")
      demoMode(emitter)
    end
    
    -- Sleep 5 seconds so we don't overwhelm The Things Network
    wait(5)		
  end
end

-- Start the Main Function
main()
```

[(__demoMode__ is explained here)](https://lupyuen.github.io/articles/roblox#appendix-particle-emitter-settings)

That's all for our demo today. Would be so fun if someday Roblox could overlay Real-World Objects through __Augmented Reality__... And show us Sensor Data in real time!

![Digital Twin with Augmented Reality](https://lupyuen.github.io/images/roblox-ar.jpg)

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

1.  __For macOS:__ If the Installer (or upgrade) fails...

    Reboot macOS.

    Delete Roblox Studio in the __Applications Folder__.
    
    Reinstall Roblox Studio.

    (That's how I fixed Roblox Studio on macOS)

To install __Roblox Studio on Linux__, see this...

-   [__"Using Roblox on Linux"__](https://roblox.fandom.com/wiki/Tutorial:Using_Roblox_on_Linux)

If we're in China, Roblox works a little differently. See this...

-   [__"Roblox China"__](https://roblox.fandom.com/wiki/Roblox_China)

# Appendix: Particle Emitter Settings

During development, we created 3 Particle Emitters...

COLD Particle Emitter (t=0)

```yaml
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
```

NORMAL Particle Emitter (t=5000)

```yaml
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
```

HOT Particle Emitter (t=10000)

```yaml
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

To render the Temperature, we performed Linear Interpolation on the three Particle Emitters above.

Based on the above values, we derive the values that will be interpolated...

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
  COLD:   5
  NORMAL: 10
  HOT:    0

LightEmission: 
  COLD:   1
  NORMAL: 0
  HOT:    0

LightInfluence: 
  COLD:   1
  NORMAL: 1
  HOT:    0

Rotation: 
  COLD:   0 180 
  NORMAL: 0 0 
  HOT:    0 0 

RotSpeed: 
  COLD:   -170 -170 
  NORMAL: 0    0 
  HOT:    0    0 

Size: 
  COLD:   0 1   0 1 1   0 
  NORMAL: 0 0.2 0 1 0.2 0 
  HOT:    0 0.4 0 1 0.4 0 
  
Speed: 
  COLD:   0 0 
  NORMAL: 5 5 
  HOT:    1 1 

SpreadAngle: 
  COLD:   10, 10
  NORMAL: 50, 50
  HOT:    50, 50
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

TODO

__demoMode__ is defined as follows: [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L264-L280)

```lua
-- Demo Mode if we don't have an IoT Device connected to The Things Network.
-- Gradually update our Particle Emitter for Temperature=10,000 to 0 and back to 10,000.
local function demoMode(emitter)
  -- Gradually update the emitter for Temperature=10,000 to 0
  for t = T_MAX, T_MIN, -600 do
    print("t:", t)
    updateParticleEmitter(emitter, t)
    wait(4)
  end
  
  -- Gradually update the emitter for Temperature=0 to 10,000
  for t = T_MIN, T_MAX, 600 do
    print("t:", t)
    updateParticleEmitter(emitter, t)
    wait(4)
  end
end
```

Here's how the Interpolating Particle Emitter looks...

-   [__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=3CP7ELTAFLg)

# Appendix: The Things Network Settings

Earlier we saw these settings for The Things Network in [DigitalTwin.lua](https://github.com/lupyuen/roblox-the-things-network/blob/main/DigitalTwin.lua#L1-L9)...

```lua
-- TODO: Change this to your Application ID for The Things Network
-- (Must have permission to Read Application Traffic)
local TTN_APPLICATION_ID = "YOUR_APPLICATION_ID"

-- TODO: Change this to your API Key for The Things Network
local TTN_API_KEY = "YOUR_API_KEY"

-- TODO: Change this to your region-specific URL for The Things Network
local TTN_URL = "https://au1.cloud.thethings.network/api/v3/as/applications/" .. TTN_APPLICATION_ID .. "/packages/storage/uplink_message?limit=1&order=-received_at"
```

This chapter explains the steps for getting the settings from The Things Network.

We assume that we have created an __Application and Device__ in The Things Network...

-   [__"Add Device to The Things Network"__](https://lupyuen.github.io/articles/ttn#add-device-to-the-things-network)

To get the __TTN_APPLICATION_ID__...

1.  Log on to [__The Things Network__](https://www.thethingsnetwork.org/)

1.  Click __Menu → Console__

    Select our region: __Europe, North America or Australia__.

1.  Copy this setting...

    __(Your Region) → Applications → (Your Application) → Application ID__

1.  Paste it here...

    ```lua
    -- TODO: Change this to your Application ID for The Things Network
    -- (Must have permission to Read Application Traffic)
    local TTN_APPLICATION_ID = "YOUR_APPLICATION_ID"
    ```

## Storage Integration

For Roblox to fetch Sensor Data from The Things Network, we shall enable __Storage Integration__...

-  [__The Things Network: Storage Integration__](https://www.thethingsindustries.com/docs/integrations/storage/)

When Storage Integration is enabled, The Things Network will __save the Uplink Messages__ transmitted by our devices.

(Saved messages will disappear after 2 or 3 days)

To enable Storage Integration, click...

__(Your Application) → Integrations → Storage Integration → Activate Storage Integration__

![The Things Network Storage Integration](https://lupyuen.github.io/images/roblox-ttn2.png)

We'll see the __Region-Specific URL__ for retrieving data...

```uri
https://au1.cloud.thethings.network/api/v3/as/
  applications/YOUR_APPLICATION_ID/
  packages/storage/uplink_message
```

The first part of the URL...

```text
au1.cloud.thethings.network
```

Depends on the region we're using: __Europe, North America or Australia__.

Copy the first part of the URL and paste into the first part of __TTN_URL__...

```lua
-- TODO: Change this to your region-specific URL for The Things Network
local TTN_URL = "https://au1.cloud.thethings.network/api/v3/as/applications/" .. TTN_APPLICATION_ID .. "/packages/storage/uplink_message?limit=1&order=-received_at"
```

("`..`" in Lua means concatenate the strings)

Our full URL for The Things Network (__TTN_URL__) looks like...

```uri
https://au1.cloud.thethings.network/api/v3/as/
  applications/YOUR_APPLICATION_ID/
  packages/storage/uplink_message
  ?limit=1&order=-received_at
```

Note that we're fetching the __Latest Uplink Message__ from The Things Network...

```text
?limit=1&order=-received_at
```

More about this in the next chapter.

## API Key

Roblox needs an __API Key__ to access the stored Uplink Messages from The Things Network.

To create an API Key, click...

__(Your Application) → API Keys → Add API Key__

![The Things Network API Key](https://lupyuen.github.io/images/roblox-ttn3.png)

Click __"Grant Individual Rights"__

Click __"Read application traffic (uplink and downlink)"__

Click __"Create API Key"__

Copy the API Key and paste here...

```lua
-- TODO: Change this to your API Key for The Things Network
local TTN_API_KEY = "YOUR_API_KEY"
```

# Appendix: Fetch Sensor Data from The Things Network

The Things Network exposes a HTTP GET API to __fetch the Uplink Messages__ transmitted by our IoT Device...

-   [__"Retrieve Uplink Messages"__](https://www.thethingsindustries.com/docs/integrations/storage/retrieve/)

(Assuming that Storage Integration is enabled. Saved messages will disappear after 2 or 3 days)

Here's the command to fetch the latest Uplink Message...

```bash
curl \
  -G "https://au1.cloud.thethings.network/api/v3/as/applications/$YOUR_APPLICATION_ID/packages/storage/uplink_message" \
  -H "Authorization: Bearer $YOUR_API_KEY" \
  -H "Accept: text/event-stream" \
  -d "limit=1" \
  -d "order=-received_at"
```

(See the previous chapter for __$YOUR_APPLICATION_ID__ and __$YOUR_API_KEY__)

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

__result.uplink_message.frm_payload__ contains the Sensor Data that we need, encoded with Base64 and CBOR...

```json
"frm_payload": "omF0GQTUYWwZCSs="
```

Our Sensor Data is encoded with [__Concise Binary Object Representation (CBOR)__](https://en.wikipedia.org/wiki/CBOR) to keep the LoRa Packets small (max 12 bytes), due to the Fair Use Policy of The Things Network...

-   [__"Fair Use of The Things Network"__](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

More about CBOR Encoding...

-   [__"Encode Sensor Data with CBOR on BL602"__](https://lupyuen.github.io/articles/cbor)
