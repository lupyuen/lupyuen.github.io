# Too many Embedded Logs? PureScript might help (Ox64 BL808 SBC / Apache NuttX RTOS)

📝 _7 Mar 2024_

![Parsing Apache NuttX RTOS Logs with PureScript](https://lupyuen.github.io/images/purescript-title.png)

[_Try the Online Demo_](https://lupyuen.github.io/nuttx-tinyemu/purescript)

[_Watch the Demo on YouTube_](https://youtu.be/9oBhy3P7pYc)

Over the Lunar New Year holidays, we were porting [__QuickJS__](https://lupyuen.github.io/articles/quickjs) to [__Ox64 BL808 SBC__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358). And we hit a [__Baffling Crash Dump__](https://github.com/lupyuen/quickjs-nuttx/blob/0aafbb7572d4d0a1f7ac48d0b6a5ac0ba8374cfc/nuttx/qemu.log#L5385-L5478) on [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html)...

![QuickJS crashes on Apache NuttX RTOS](https://lupyuen.github.io/images/quickjs-stack.webp)

Which made us ponder...

- Can we show the [__RISC-V Exception__](https://github.com/lupyuen/quickjs-nuttx/blob/0aafbb7572d4d0a1f7ac48d0b6a5ac0ba8374cfc/nuttx/qemu.log#L5385) prominently?

  (Without scrolling back pages and pages of logs)

- And [__Explain the Exception__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#sec:mcause)

  (For folks new to RISC-V Exceptions)

- Analyse the [__Stack Dump__](https://github.com/lupyuen/quickjs-nuttx/blob/0aafbb7572d4d0a1f7ac48d0b6a5ac0ba8374cfc/nuttx/qemu.log#L5402-L5469) to point out Interesting Addresses

  (For Code, Data, BSS, Heap, ...)

![Parsing Apache NuttX RTOS Logs with PureScript (Overall Flow)](https://lupyuen.github.io/images/purescript-flow.jpg)

In this article, we create a __NuttX Log Parser__ that will...

- Extract the [__RISC-V Exception Details__](https://lupyuen.github.io/images/purescript-parse4.png)

- Interpret and [__Explain the RISC-V Exception__](https://lupyuen.github.io/images/purescript-parse4.png)

- Hyperlink the [__Stack Dump__](https://lupyuen.github.io/images/purescript-parse5.png) to NuttX Source Code and Disassembly

And we'll do this in [__PureScript__](https://www.purescript.org/), the Functional Programming Language that compiles to JavaScript.

(We'll see why in a moment)

![Parsing Apache NuttX RTOS Logs with PureScript](https://lupyuen.github.io/images/purescript-title.png)

[_Watch the Demo on YouTube_](https://youtu.be/9oBhy3P7pYc)

# Demo Walkthrough

To see our __NuttX Log Parser__ in action, we run the [__NuttX Emulator__](https://lupyuen.github.io/articles/tinyemu2) in a Web Browser. (Pic above)

Inside the NuttX Emulator is the exact same __NuttX App (QuickJS)__ that crashed over the holidays...

1.  Head over to this link...

    [__Emulator for Ox64 BL808 SBC__](https://lupyuen.github.io/nuttx-tinyemu/purescript)

1.  __Apache NuttX RTOS__ boots on the Ox64 Emulator...

    And starts our NuttX App: __QuickJS__

    Our NuttX App crashes with a [__RISC-V Exception__](https://github.com/lupyuen/quickjs-nuttx/blob/0aafbb7572d4d0a1f7ac48d0b6a5ac0ba8374cfc/nuttx/qemu.log#L5385-L5478)...

    ![NuttX App crashes with a RISC-V Exception](https://lupyuen.github.io/images/purescript-parse3.png)

1.  The [__Terminal Output__](https://github.com/lupyuen/quickjs-nuttx/blob/0aafbb7572d4d0a1f7ac48d0b6a5ac0ba8374cfc/nuttx/qemu.log#L5385-L5478) at left shows pages and pages of logs.

    (As seen by NuttX Devs today)

    But something helpful appears at the right...

1.  The NuttX Log Parser shows the __RISC-V Exception Info__

    Followed by the __Explanation of the Exception__...

    ![RISC-V Exception Info and Explanation](https://lupyuen.github.io/images/purescript-parse4.png)

    And the __Stack Dump__...

    ![Stack Dump](https://lupyuen.github.io/images/purescript-parse5.png)

1.  The __NuttX Addresses__ are clickable.

    Clicking an address brings us to the __NuttX Disassembly__

    Which links to the __NuttX Source Code__. (Pic below)

    [(Watch the __Demo on YouTube__)](https://youtu.be/9oBhy3P7pYc)

![NuttX Disassembly](https://lupyuen.github.io/images/purescript-disassembly.png)

_What just happened?_

Our NuttX App crashed on NuttX RTOS, producing tons of logs.

But thanks to the NuttX Log Parser, we extracted and interpreted the interesting bits: __Exception Info, Exception Explanation__ and __Stack Dump__.

(With hyperlinks to __NuttX Disassembly__ and __Source Code__)

How did we make it happen? We start with the smarty bits...

![Explain the RISC-V Exception](https://lupyuen.github.io/images/purescript-flow2.jpg)

# Explain the RISC-V Exception

_How did we explain the RISC-V Exception?_

<span style="font-size:90%">

> "We hit a Load Page Fault. Our code at Code Address 8000a0e4 tried to access the Data Address 880203b88, which is Invalid"

</span>

That's our message that explains the __RISC-V Exception__...

<span style="font-size:90%">

- __MCAUSE 13__: Cause of Exception

- __EPC `8000_A0E4`__: Exception Program Counter

- __MTVAL `8_8020_3B88`__: Exception Value

</span>

__In PureScript:__ This is how we compose the helpful message: [Main.purs](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L29-L55)

```purescript
-- Explain the RISC-V Exception with mcause 13
-- `<>` will concat 2 strings

explainException 13 epc mtval =
  "We hit a Load Page Fault."
  <> " Our code at Code Address " <> epc
  <> " tried to access the Data Address " <> mtval
  <> ", which is Invalid."
```

_Hello Marvin the Martian?_

Yeah we'll meet some alien symbols in PureScript.

'__`<>`__' _(Diamond Operator)_ will __concatenate 2 strings__.

We explain the other RISC-V Exceptions the same way: [Main.purs](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L46-L55)

```purescript
-- TODO: Explain the RISC-V Exception with mcause 12
-- `<>` will concat 2 strings
-- "🎵 I never promised you a rose garden"

explainException 12 epc mtval =
  "Instruction Page Fault at " <> epc <> ", " <> mtval

-- TODO: Explain the Other RISC-V Exceptions,
-- that are not matched with the above.
-- `show` converts a Number to a String

explainException mcause epc mtval =
  "Unknown Exception: mcause=" <> show mcause <> ", epc=" <> epc <> ", mtval=" <> mtval
```

Which looks like a tidy bunch of __Explain Rules__. (Similar to Prolog!)

This thing about PureScript looks totally alien: [Main.purs](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L29-L38)

```purescript
-- Declare the Function Type.
-- We can actually erase it, VSCode PureScript Extension will helpfully suggest it for us.

explainException ::
  Int        -- MCAUSE: Cause of Exception
  -> String  -- EPC: Exception Program Counter
  -> String  -- MTVAL: Exception Value
  -> String  -- Returns the Exception Explanation
```

But it works like a __Function Declaration__ in C.

[(__VSCode__ will generate the declaration)](https://lupyuen.github.io/articles/purescript#appendix-nuttx-log-parser)

_How will we call this from JavaScript?_

Inside our __Web Browser JavaScript__, this is how we call PureScript: [index.html](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/index.html#L28-L33)

```javascript
// In JavaScript: Import our PureScript Function
import { explainException } from './output/Main/index.js';

// Call PureScript via a Curried Function.
// Returns "Code Address 8000a0e4 failed to access Data Address 880203b88"
result = explainException(13)("8000a0e4")("880203b88");

// Instead of the normal non-spicy Uncurried Way:
// explainException(13, "8000a0e4", "880203b88")
```

Our JavaScript will call PureScript the (yummy) [__Curried Way__](https://javascript.info/currying-partials), because PureScript is a Functional Language.

[(Try __PureScript Online__)](https://lupyuen.github.io/articles/purescript#appendix-online-purescript-compiler)

![PureScript looks like a neat way to express our NuttX Troubleshooting Skills as high-level rules](https://lupyuen.github.io/images/purescript-explain.png)

_Why PureScript? Could've done all this in JavaScript..._

PureScript looks like a neat way to express our __NuttX Troubleshooting Skills__ as high-level rules...

Without getting stuck with the low-level procedural plumbing of JavaScript.

Let's do a bit more PureScript...

![Parse the RISC-V Exception](https://lupyuen.github.io/images/purescript-flow3.jpg)

# Parse the RISC-V Exception

_How did we get the RISC-V Exception? MCAUSE, EPC, MTVAL?_

We auto-extracted the __RISC-V Exception__ from the NuttX Log...

```yaml
riscv_exception:
  EXCEPTION: Load page fault.
  MCAUSE:    000000000000000d,
  EPC:       000000008000a0e4,
  MTVAL:     0000000880203b88
```

PureScript really shines for __Parsing Text Strings__. We walk through the steps: [Main.purs](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L136-L208)

```purescript
-- Declare our Function to Parse the RISC-V Exception
parseException :: Parser  -- We're creating a Parser...
  {                       -- That accepts a String and returns...
    exception  :: String  -- Exception: `Load page fault`
  , mcause     :: Int     -- MCAUSE: 13
  , epc        :: String  -- EPC: `8000a0e4`
  , mtval      :: String  -- MTVAL: `0000000880203b88`
  }
```

[(__VSCode__ will generate the declaration)](https://lupyuen.github.io/articles/purescript#appendix-nuttx-log-parser)

We're about to create a __PureScript String Parser__ that will accept a printed RISC-V Exception and return the MCAUSE, EPC and MTVAL.

This is how we write our __Parsing Function__: [Main.purs](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L148-L208)

```purescript
-- To parse the line: `riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 000000008000a0e4, MTVAL: 0000000880203b88`
parseException = do

  -- Skip `riscv_exception: EXCEPTION: `
  void $
    string "riscv_exception:" -- Match the string `riscv_exception:`
    <* skipSpaces             -- Skip the following spaces
    <* string "EXCEPTION:"    -- Match the string `EXCEPTION:`
    <* skipSpaces             -- Skip the following spaces
```

As promised, please meet our alien symbols...

- __`void`__ means ignore the text

  (Similar to C)

- __`$` `something` `something`__

  is shortcut for...

  __`(` `something` `something` `)`__

- __`<*`__ is the Delimiter between Patterns

  (Looks like an alien raygun)

Which will skip the unnecessary prelude...

```text
riscv_exception: EXCEPTION: 
```

Next comes the __Exception Message__, which we'll capture via a __Regular Expression__ (and an alien raygun)

```purescript
  -- `exception` becomes `Load page fault`
  -- `<*` says when we should stop the Text Capture
  exception <- regex "[^.]+" 
    <* string "." 
    <* skipSpaces 
```

We do the same to capture __MCAUSE__ (as a String)

```purescript
  -- Skip `MCAUSE: `
  -- `void` means ignore the Text Captured
  -- `$ something something` is shortcut for `( something something )`
  -- `<*` is the Delimiter between Patterns
  void $ string "MCAUSE:" <* skipSpaces

  -- `mcauseStr` becomes `000000000000000d`
  -- We'll convert to integer later
  mcauseStr <- regex "[0-9a-f]+" <* string "," <* skipSpaces
```

Then we capture __EPC__ and __MTVAL__ (with the Zero Prefix)

```purescript
  -- Skip `EPC: `
  -- `epcWithPrefix` becomes `000000008000a0e4`
  -- We'll strip the prefix `00000000` later
  void $ string "EPC:" <* skipSpaces
  epcWithPrefix <- regex "[0-9a-f]+" <* string "," <* skipSpaces

  -- Skip `MTVAL: `
  -- `mtvalWithPrefix` becomes `0000000880203b88`
  -- We might strip the zero prefix later
  void $ string "MTVAL:" <* skipSpaces
  mtvalWithPrefix <- regex "[0-9a-f]+"
```

Finally we return the parsed __MCAUSE__ (as integer), __EPC__ (without prefix), __MTVAL__ (without prefix)

```purescript
  -- Return the parsed content.
  -- `pure` because we're in a `do` block that allows (Side) Effects
  -- TODO: Return a ParseError instead of -1
  pure 
    {
      exception
    , mcause:
        -1 `fromMaybe` -- If `mcauseStr` is not a valid hex, return -1
          fromStringAs hexadecimal mcauseStr -- Else return the hex value of `mcauseStr`
    , epc:
        epcWithPrefix `fromMaybe` -- If `epcWithPrefix` does not have prefix `00000000`, return it
          stripPrefix (Pattern "00000000") epcWithPrefix -- Else strip prefix `00000000` from `epc`
    , mtval:
        mtvalWithPrefix `fromMaybe` -- If `mtvalWithPrefix` does not have prefix `00000000`, return it
          stripPrefix (Pattern "00000000") mtvalWithPrefix -- Else strip prefix `00000000` from `mtval`
    }
```

<span style="font-size:90%">

[(__fromMaybe__ resolves an Optional Value)](https://pursuit.purescript.org/packages/purescript-maybe/docs/Data.Maybe#v:fromMaybe)

[(__fromStringAs__ converts String to Integer)](https://pursuit.purescript.org/packages/purescript-integers/docs/Data.Int#v:fromStringAs)

[(__stripPrefix__ removes the String Prefix)](https://pursuit.purescript.org/packages/purescript-strings/6.0.1/docs/Data.String#v:stripPrefix)

</span>

_fromMaybe looks weird?_

We tried to make our code "friendlier"...

```purescript
a `fromMaybe` b
```

Is actually equivalent to the Bracket Bonanza...

```purescript
(fromMaybe a b)
```

(Maybe we tried too hard)

_Does it work with JavaScript?_

Yep it does! This is how we __parse a RISC-V Exception__ in JavaScript: [index.html](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/index.html#L17-L28)

```javascript
// In JavaScript: Import our PureScript Parser
import { parseException } from './output/Main/index.js';
import * as StringParser_Parser from "./output/StringParser.Parser/index.js";

// We'll parse this RISC-V Exception
const exception = `riscv_exception: EXCEPTION: Load page fault. MCAUSE: 000000000000000d, EPC: 000000008000a0e4, MTVAL: 0000000880203b88`;

// Call PureScript to parse the RISC-V Exception
const result = StringParser_Parser
  .runParser(parseException)(exception);
```

Which returns the __JSON Result__...

```json
{
  "value0": {
    "exception": "Load page fault",
    "mcause":    13,
    "epc":       "8000a0e4",
    "mtval":     "0000000880203b88"
  }
}
```

And it works great with our [__RISC-V Exception Explainer__](https://lupyuen.github.io/articles/purescript#explain-the-risc-v-exception)!

```javascript
// In JavaScript: Import our Exception Explainer from PureScript
import { explainException } from './output/Main/index.js';

// Fetch the Parsed RISC-V Exception from above
// TODO: If the parsing failed, then exception === undefined
const exception = result.value0;

// Explain the Parsed RISC-V Exception.
// Returns "We hit a Load Page Fault. Our code at Code Address 8000a0e4 tried to access the Data Address 0000000880203b88, which is Invalid."
const explain = explainException
  (exception.mcause)
  (exception.epc)
  (exception.mtval);
```

Let's talk about log passing (and tossing)...

![Pass NuttX Logs to PureScript](https://lupyuen.github.io/images/purescript-flow4.jpg)

# Pass NuttX Logs to PureScript

_PureScript will parse our RISC-V Exceptions and explain them... How to pass our NuttX Logs to PureScript?_

We're running [__NuttX Emulator__](https://lupyuen.github.io/articles/tinyemu2) inside our Web Browser.

We __intercept all logs__ emitted by the Emulator, with this JavaScript: [term.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/term.js#L487-L511)

```javascript
// When NuttX Emulator prints something
// to the Terminal Output...
Term.prototype.write = function(ch) {

  // Send it to our NuttX Log Parser
  parseLog(ch);
```

Our JavaScript __parses NuttX Logs__ like this: [term.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/term.js#L1483-L1575)

```javascript
// Parse NuttX Logs with PureScript.
// Assume `ch` is a single character for Terminal Output.
// PureScript Parser is inited in `index.html`
function parseLog(ch) {

  // Omitted: Accumulate the characters into a line.
  // Ignore Newlines and Carriage Returns
  termbuf += ch;
  ...
  // Parse the RISC-V Exception
  // TODO: Check for exception.error === undefined
  const exception = StringParser_Parser
    .runParser(parseException)(termbuf)
    .value0;

  // Explain the Exception
  const explain = explainException
    (exception.mcause)
    (exception.epc)
    (exception.mtval);
```

Line by line, we pass the NuttX Logs to PureScript, to __parse the RISC-V Exceptions__ and explain them.

Then we display everything...

```javascript
  // Link the Exception to the Disassembly
  const epc   = disassemble(exception.epc);
  const mtval = disassemble(exception.mtval);
  const exception_str = [
    "Exception:" + exception.exception,
    "MCAUSE:"    + exception.mcause,
    "EPC:"       + epc,
    "MTVAL:"     + mtval,
  ].join("<br>");

  // Display the Exception
  const parser_output = document.getElementById("parser_output");
  parser_output.innerHTML +=
    `<p>${exception_str}</p>`;

  // Display the Exception Explanation
  parser_output.innerHTML +=
    `<p>${explain}</p>`
    .split(exception.epc,   2).join(epc)     // Link EPC to Disassembly
    .split(exception.mtval, 2).join(mtval);  // Link MTVAL to Disassembly
```

(We'll see __disassemble__ later)

We do the same for the __Stack Dump__...

```javascript
  // Parse the Stack Dump and link to the Disassembly
  // TODO: Check for stackDump.error === undefined
  const stackDump = StringParser_Parser
    .runParser(parseStackDump)(termbuf)
    .value0;

  // Display the Stack Dump
  const str = [
    stackDump.addr + ":",
    disassemble(stackDump.v1), disassemble(stackDump.v2), disassemble(stackDump.v3), disassemble(stackDump.v4),
    disassemble(stackDump.v5), disassemble(stackDump.v6), disassemble(stackDump.v7), disassemble(stackDump.v8),
  ].join("&nbsp;&nbsp;");
  parser_output.innerHTML +=
    `<p>${str}</p>`;

  // Reset the Line Buffer
  termbuf = "";
}

// Buffer the last line of the Terminal Output
let termbuf = "";
```

<span style="font-size:90%">

[(__parseStackDump__ comes from PureScript)](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L208-L275)

[(__NuttX Emulator__ imports PureScript like this)](https://lupyuen.github.io/articles/purescript#appendix-rewrite-the-imports)

</span>

_Will this work for a Real NuttX Device?_

NuttX on Ox64 BL808 SBC runs in a Web Browser with [__Web Serial API and Term.js__](https://lupyuen.github.io/articles/quickjs2#control-ox64-via-web-serial-api).

We'll intercept and parse the NuttX Logs in Term.js, the exact same way as above.

_What's this function: disassemble?_

Instead of printing addresses plainly like `8000a0e4`, we show __Addresses as Hyperlinks__...

```text
<a href="disassemble.html?addr=8000a0e4" target="_blank">
  8000a0e4
</a>
```

Which links to our page that displays the __NuttX Disassembly__ for the address: [term.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/term.js#L1556-L1571)

```javascript
// If `addr` is a valid address,
// wrap it with the Disassembly URL:
// <a href="disassemble.html?addr=8000a0e4" target="_blank">8000a0e4</a>
// Otherwise return `addr`
function disassemble(addr) {

  // If this is an Unknown Address:
  // Return it without hyperlink
  const id = identifyAddress(addr).value0;
  if (id === undefined) { return addr; }

  // Yep `addr` is a valid address.
  // Wrap it with the Disassembly URL
  const url = `disassemble.html?addr=${addr}`;
  return [
    `<a href="${url}" target="_blank">`,
    addr,
    `</a>`,
  ].join("");
}
```

But we do this only for __Valid NuttX Addresses__. (Otherwise we'll hyperlink to hot garbage)

How will __identifyAddress__ know if it's a Valid NuttX Address? Coming right up...

![Identify a NuttX Address](https://lupyuen.github.io/images/purescript-flow5.jpg)

# Identify a NuttX Address

_Given a NuttX Address like 8000a0e4: How will we know if it's in NuttX Kernel or NuttX App? And whether it's Code, Data, BSS or Heap?_

Once Again: We get a little help from __PureScript__ to match the Regex Patterns of __Valid NuttX Addresses__: [Main.purs](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L55-L102)

```purescript
-- Given an Address: Identify the
-- Origin (NuttX Kernel or App) and
-- Type (Code / Data / BSS / Heap)
identifyAddress addr

  -- `|` works like `if ... else if`
  -- "a `matches` b" is same as "(matches a b)"
  -- `Just` returns an OK Value. `Nothing` returns No Value.

  -- Address 502xxxxx comes from NuttX Kernel Code
  | "502....." `matches` addr =
    Just { origin: "nuttx", type: Code }

  -- Address 800xxxxx comes from NuttX App Code (QuickJS)
  | "800....." `matches` addr =
    Just { origin: "qjs",   type: Code }

  -- Otherwise it's an Unknown Address
  | otherwise = Nothing
```

<span style="font-size:90%">

[(__matches__ does __Regex Matching__)](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L84-L102)

[(__Addresses as Numbers__ instead of Strings)](https://lupyuen.github.io/articles/purescript#appendix-bigint-in-purescript)

</span>

_How does it work?_

The code above is called by our JavaScript to __Identify NuttX Addresses__: [index.html](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/index.html#L44-L58)

```javascript
// In JavaScript: Call PureScript to Identify a NuttX Address.
import { identifyAddress } from './output/Main/index.js';

// For NuttX Kernel Address:
// Returns {value0: {origin: "nuttx", type: {}}
result = identifyAddress("502198ac");

// For NuttX App Address:
// Returns {value0: {origin: "qjs", type: {}}
result = identifyAddress("8000a0e4");

// Why is the `type` empty? That's because it's a
// JavaScript Object that needs extra inspection.
// This will return "Code" or "Data" or "BSS" or "Heap"...
addressType = result.value0.type.constructor.name;

// Unknown Address returns {}
result = identifyAddress("0000000800203b88");

// This will return "Nothing"
resultType = result.constructor.name;
```

_Tsk tsk we're hard-coding Address Patterns?_

Our __Troubleshooting Rules__ are still evolving, we're not sure how the NuttX Log Parser will be used in future.

That's why we'll have an [__Online PureScript Compiler__](https://lupyuen.github.io/articles/purescript#appendix-online-purescript-compiler) that will allow the Troubleshooting Rules to be __tweaked and tested easily__ across all NuttX Platforms.

![NuttX Disassembly](https://lupyuen.github.io/images/purescript-disassembly.png)

[_NuttX Disassembly for 8000_702A_](https://lupyuen.github.io/nuttx-tinyemu/purescript/disassemble.html?addr=8000702a)

# Disassemble NuttX by Address

_Given a NuttX Address like 8000a0e4: How shall we show the NuttX Disassembly?_

We chunked up the __NuttX Disassembly__ into many many small files (by NuttX Address)...

```bash
## NuttX App Dissassembly (QuickJS)
## Chunked into 101 small files
$ ls nuttx-tinyemu/docs/purescript/qjs-chunk
qjs-80001000.S
qjs-80002000.S
...
qjs-80063000.S
qjs-80064000.S
qjs-80065000.S
```

[(See the __Disassembly Chunks__)](https://github.com/lupyuen/nuttx-tinyemu/tree/main/docs/purescript/qjs-chunk)

So __`8000a0e4`__ will appear in the file [__qjs-8000b000.S__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-8000b000.S#L171)

```c
// NuttX Disassembly for 8000a0e4
quickjs-nuttx/quickjs.c:2876
  p = rt->atom_array[i];
    8000a0e4:  6380  ld  s0,0(a5)
```

Which gets hyperlinked in our [__NuttX Log Display__](https://lupyuen.github.io/nuttx-tinyemu/purescript/disassemble.html?addr=8000a0e4) whenever `8000a0e4` is shown...

```text
<a href="disassemble.html?addr=8000a0e4" target="_blank">
  8000a0e4
</a>
```

_What's inside disassemble.html? (Pic above)_

Given a __NuttX Address__ like __`8000a0e4`__...

```text
disassemble.html?addr=8000a0e4
```

[__disassemble.html__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/disassemble.js) will...

1.  Fetch the Disassembly Chunk File: [__qjs-8000b000.S__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-8000b000.S#L171)

1.  Search for address [__`8000a0e4`__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-8000b000.S#L171) in the file

1.  Display 20 lines of [__NuttX Disassembly__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-8000b000.S#L151-L190) before and after the address

1.  Hyperlink to the [__NuttX Source Code__](https://github.com/lupyuen/quickjs-nuttx/blob/master/quickjs.c#L2877)...

    ```text
    <a href="https://github.com/lupyuen/quickjs-nuttx/blob/master/quickjs.c#L2877" target="_blank">
      quickjs-nuttx/quickjs.c:2877
    </a>
    ```

[(More about __disassemble.html__)](https://github.com/lupyuen/nuttx-purescript-parser#show-nuttx-disassembly-by-address)

_How do we chunk a NuttX Dissassembly?_

We created a [__NuttX Disassembly Chunker__](https://github.com/lupyuen/nuttx-disassembly-chunker/blob/main/src/main.rs) that will...

- Split a huge __NuttX Disassembly__: [qjs.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs.S)

- Into smaller __Disassembly Chunk Files__: [qjs-chunk/qjs-80001000.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-80001000.S)

- So that Disassembly Address __`0x8000_0000`__ goes into [qjs-80001000.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-80001000.S)

- And Disassembly Address __`0x8000_1000`__ goes into [qjs-80002000.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-80002000.S), ...

We run the chunker like this...

```bash
## Dump the NuttX Disassembly
## for NuttX ELF qjs
riscv64-unknown-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  $HOME/qjs \
  >$HOME/qjs.S \
  2>&1

## Chunk the NuttX Disassembly
## at $HOME/qjs.S into
## $HOME/qjs-chunk/qjs-80001000.S
## $HOME/qjs-chunk/qjs-80002000.S
## ...
chunkpath=$HOME
chunkbase=qjs
mkdir -p $chunkpath/$chunkbase-chunk
rm -f $chunkpath/$chunkbase-chunk/*

## Run the NuttX Disassembly Chunker
## TODO: Edit the pathnames in https://github.com/lupyuen/nuttx-disassembly-chunker/blob/main/src/main.rs#L81-L91
git clone https://github.com/lupyuen/nuttx-disassembly-chunker
cd nuttx-disassembly-chunker
cargo run -- $chunkpath $chunkbase
```

[(See the __Disassembly Chunks__)](https://github.com/lupyuen/nuttx-tinyemu/tree/main/docs/purescript/qjs-chunk)

![Parsing Apache NuttX RTOS Logs with PureScript (Overall Flower)](https://lupyuen.github.io/images/purescript-flower.jpg)

# What's Next

TODO: [Solution is here](https://lupyuen.github.io/articles/quickjs#nuttx-stack-is-full-of-quickjs)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/purescript.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/purescript.md)

![NuttX Log Parser](https://lupyuen.github.io/images/purescript-flow6.jpg)

# Appendix: NuttX Log Parser

If we wish to update the __NuttX Log Parser__ in PureScript: This is how we download and build the code...

```bash
## Download the NuttX Log Parser in PureScript
git clone https://github.com/lupyuen/nuttx-purescript-parser
cd nuttx-purescript-parser

## Edit our code in `src/Main.purs`
code .

## Build and Run the NuttX Log Parser
spago run

## Deploy to GitHub Pages in `docs` folder
## https://lupyuen.github.io/nuttx-purescript-parser/
./run.sh
```

__"`spago` `run`"__ will compile our NuttX Log Parser and generate...

- [__output/Main/index.js__](https://github.com/lupyuen/nuttx-purescript-parser/releases/download/main-1/index.js)

- [__output/\<Other JavaScript Modules\>__](https://github.com/lupyuen/nuttx-purescript-parser/releases/download/main-1/output.zip)

[__run.sh__](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/run.sh) will rewrite the __JavaScript Imports__. (See the next section)

Remember to install the [__PureScript IDE VSCode Extension__](https://marketplace.visualstudio.com/items?itemName=nwolverson.ide-purescript). It will auto-generate the __Function Types__ when we click on the Suggested Type...

![VSCode will auto-generate the Function Types when we click on the Suggested Type](https://lupyuen.github.io/images/purescript-type.png)

# Appendix: Rewrite the Imports

From the previous section, __PureScript Compiler "`spago` `run`"__ generates the JavaScript for our NuttX Log Parser at...

- [__output/Main/index.js__](https://github.com/lupyuen/nuttx-purescript-parser/releases/download/main-1/index.js)

- [__output/\<Other JavaScript Modules\>__](https://github.com/lupyuen/nuttx-purescript-parser/releases/download/main-1/output.zip)

Which means we need to deploy the __Other JavaScript Modules__. But there's a workaround...

Here's how we __rewrite the JavaScript__ (generated by PureScript Compiler), so it points the JavaScript Imports to __compile.purescript.org__: [run.sh](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/run.sh)

```bash
## Change:
##   import { ... } from './output/Main/index.js';
## To:
##   import { ... } from './index.js';

## Change:
##   import * as StringParser_Parser from "./output/StringParser.Parser/index.js";
## To:
##   import * as StringParser_Parser from "https://compile.purescript.org/output/StringParser.Parser/index.js";

cat index.html \
  | sed 's/output\/Main\///' \
  | sed 's/.\/output\//https:\/\/compile.purescript.org\/output\//' \
  >docs/index.html

## Change:
##   import * as Control_Alt from "../Control.Alt/index.js";
## To:
##   import * as Control_Alt from "https://compile.purescript.org/output/Control.Alt/index.js";

cat output/Main/index.js \
  | sed 's/from \"../from \"https:\/\/compile.purescript.org\/output/' \
  >docs/index.js
```

[(__index.html__ is our Test JavaScript)](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/index.html)

This produces the __Modified JavaScript__: [docs/index.js](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/docs/index.js)

Which gets published at [nuttx-purescript-parser/index.js](https://lupyuen.github.io/nuttx-purescript-parser/index.js)

[(See the __Modified JavaScript__)](https://github.com/lupyuen/nuttx-purescript-parser/tree/main/docs)

[(Run the __Modified JavaScript__)](https://lupyuen.github.io/nuttx-purescript-parser/)

_How is this JavaScript imported by NuttX Emulator?_

NuttX Emulator imports the __Modified JavaScript__ for NuttX Log Parser like this: [index.html](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/index.html#L48-L61)

```javascript
<script type=module>
  // Import the NuttX Log Parser
  import { parseException, parseStackDump, explainException, identifyAddress }
    from 'https://lupyuen.github.io/nuttx-purescript-parser/index.js';
  import * as StringParser_Parser
    from "https://compile.purescript.org/output/StringParser.Parser/index.js";

  // Allow other modules to call the PureScript Functions
  window.StringParser_Parser = StringParser_Parser;
  window.parseException   = parseException;
  window.parseStackDump   = parseStackDump;
  window.explainException = explainException;
  window.identifyAddress  = identifyAddress;

  // Call the PureScript Function
  const result2 = explainException(12)('000000008000ad8a')('000000008000ad8a')
```

# Appendix: BigInt in PureScript

_Why are we passing addresses in Text instead of Numbers? Like `"8000ad8a"`_

That's because `0x8000ad8a` is too big for __PureScript Int__, a signed 32-bit integer.

PureScript Int is meant to interoperate with JavaScript Integer, which is also 32-bit.

_What about PureScript BigInt?_

```bash
spago install bigints
npm install big-integer
```

If we use [__PureScript BigInt__](https://pursuit.purescript.org/packages/purescript-bigints/docs/Data.BigInt), then we need [__NPM big-integer__](https://www.npmjs.com/package/big-integer).

But NPM big-integer won't run inside a Web Browser with Plain Old JavaScript. That's why we're passing addresses as Strings instead of Numbers.

__TODO:__ BigInt is [__already supported__](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) by Web Browsers. Do we really need NPM big-integer?

![Online PureScript Compiler](https://lupyuen.github.io/images/purescript-compiler.png)

[_Try the Online PureScript Compiler_](https://lupyuen.github.io/nuttx-trypurescript?gist=1405685d6f847ea5d4d6302b196bb05e)

# Appendix: Online PureScript Compiler

_How will we allow the NuttX Troubleshooting Rules to be tweaked and tested easily across all NuttX Platforms?_

The __Online PureScript Compiler__ will let us modify and test the NuttX Troubleshooting Rules in a Web Browser (pic above)...

1.  Head over to our [__Online PureScript Compiler__](https://lupyuen.github.io/nuttx-trypurescript?gist=1405685d6f847ea5d4d6302b196bb05e)

    Which compiles our __NuttX Log Parser__ (from PureScript to JavaScript)

1.  Our __NuttX Log Parser__ runs in the Web Browser...

    ```text
    We hit a Load Page Fault. Our code at Code Address 8000a0e4 tried to access the Data Address 0000000880203b88, which is Invalid.
    Instruction Page Fault at epc, mtval
    Unknown Exception: mcause=0, epc=epc, mtval=mtval
    (Just { origin: "nuttx", type: Code })
    (Just { origin: "qjs", type: Code })
    Nothing
    (runParser) Parsing content with 'parseException'
    Result: { epc: "8000ad8a", exception: "Instruction page fault", mcause: 12, mtval: "8000ad8a" }
    -----
    (runParser) Parsing content with 'parseStackDump'
    Result: { addr: "c02027e0", v1: "c0202010", v2: "00000000", v3: "00000001", v4: "00000000", v5: "00000000", v6: "00000000", v7: "8000ad8a", v8: "00000000" }
    -----
    (runParser) Parsing content with 'parseStackDump'
    Result: { addr: "c02027e0", v1: "c0202010", v2: "00000000", v3: "00000001", v4: "00000000", v5: "00000000", v6: "00000000", v7: "8000ad8a", v8: "00000000" }
    -----
    ```

1.  Try tweaking the rules for __explainException__...

    ```purescript
    explainException 13 epc mtval =
      "We hit a Load Page Fault."
      <> " Our code at Code Address " <> epc
      <> " tried to access the Data Address " <> mtval
      <> ", which is Invalid."
    ```

    And __identifyAddress__...

    ```purescript
    identifyAddress addr
      | "502....." `matches` addr = Just { origin: "nuttx", type: Code }
      | "800....." `matches` addr = Just { origin: "qjs",   type: Code }
      | otherwise = Nothing
    ```

    The changes will take effect immediately.

    [(Watch the __Demo on YouTube__)](https://youtu.be/wbycFBQho_E)

1.  __Future Plans:__ We'll copy the Generated JavaScript to NuttX Emulator via [__JavaScript Local Storage__](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API/Using_the_Web_Storage_API).

    So we can test our Modified NuttX Log Parser on the Actual NuttX Logs.

    The [__PureScript Compiler Web Service__](https://github.com/lupyuen/nuttx-purescript-parser#compile-purescript-to-javascript-in-web-browser) is super helpful for compiling our PureScript Code to JavaScript, inside our Web Browser.

    [(See the __Generated JavaScript__)](https://github.com/lupyuen/nuttx-purescript-parser#purescript-editor-for-nuttx)

![Parsing Apache NuttX RTOS Logs with PureScript (Overall Flowest)](https://lupyuen.github.io/images/purescript-flowest.jpg)

If we wish to run the Online PureScript Compiler locally on our computer...

```bash
## Download the Online PureScript Compiler
git clone https://github.com/lupyuen/nuttx-trypurescript
cd nuttx-trypurescript
cd client

## To Build and Test Locally:
## This produces `output` folder
## and `public/js/index.js`
## Test at http://127.0.0.1:8080?gist=1405685d6f847ea5d4d6302b196bb05e
npm install
npm run serve:production

## To Deploy to GitHub Pages in `docs` folder:
rm -r ../docs
cp -r public ../docs

## To Test Locally the GitHub Pages in `docs` folder:
## http://0.0.0.0:8000/docs/index.html?gist=1405685d6f847ea5d4d6302b196bb05e
cargo install simple-http-server
simple-http-server .. &
```

The Test Code comes from our [__GitHub Gist__](https://gist.github.com/lupyuen/1405685d6f847ea5d4d6302b196bb05e).
