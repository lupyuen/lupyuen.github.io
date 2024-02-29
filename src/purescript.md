# Too many Embedded Logs? PureScript might help (Ox64 BL808 SBC / Apache NuttX RTOS)

📝 _7 Mar 2024_

![TODO](https://lupyuen.github.io/images/purescript-title.png)

Over the Lunar New Year holidays, we were porting [__QuickJS__](TODO) to [__Ox64 BL808 SBC__](TODO). And we hit a __Baffling Exception__ on [__Apache NuttX RTOS__](TODO)...

TODO: Pic

Which made us ponder (our life choices)...

- Can we show the __RISC-V Exception__ promimently?

  (Without scrolling back pages and pages of logs)

- And __Explain the Exception__

  (For folks new to RISC-V Exceptions)

- Analyse the __Stack Dump__ and point out Interesting Addresses

  (For Code, Data, BSS, Heap, ...)

In this article, 

[__Ox64 BL808 64-bit RISC-V SBC__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358)

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html)

[__QuickJS for NuttX__](https://lupyuen.github.io/articles/quickjs)

[__TinyEMU WebAssembly for NuttX__](https://lupyuen.github.io/articles/tinyemu2)

[__Web Serial API__](https://developer.chrome.com/docs/capabilities/serial) with [__Term.js__](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/blockly/term.js)

![Parsing Apache NuttX RTOS Logs with PureScript](https://lupyuen.github.io/images/purescript-title.png)

[(Try the Online Demo)](https://lupyuen.github.io/nuttx-tinyemu/purescript)

[(Watch the Demo on YouTube)](https://youtu.be/9oBhy3P7pYc)

# Demo Walkthrough

TODO

We begin with the smarty stuff...

# Explain the RISC-V Exception

_How did we explain the RISC-V Exception?_

> "We hit a Load Page Fault. Our code at Code Address 8000a0e4 tried to access the Data Address 880203b88, which is Invalid"

That's our message that explains the __RISC-V Exception__...

- __MCAUSE 13__: Cause of Exception

- __EPC `8000_A0E4`__: Exception Program Counter

- __MTVAL `8_8020_3B88`__: Exception Value

__In PureScript:__ This is how we compose the helpful message: [Main.purs](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L29-L51)

```purescript
-- Explain the RISC-V Exception with mcause 13
-- `<>` will concat 2 strings
-- "🎵 I never promised you a rose garden"

explainException 13 epc mtval =
  "We hit a Load Page Fault."
  <> " Our code at Code Address " <> epc
  <> " tried to access the Data Address " <> mtval
  <> ", which is Invalid."
```

_Hello Marvin the Martian?_

Yeah we'll meet some alien symbols in PureScript.

'__`<>`__' _(Diamond Operator)_ will __concatenate 2 strings__.

We explain the other RISC-V Exceptions the same way...

```purescript
-- Explain the RISC-V Exception with mcause 12
-- `<>` will concat 2 strings

explainException 12 epc mtval =
  "Instruction Page Fault at " <> epc <> ", " <> mtval

-- Explain the Other RISC-V Exceptions,
-- that are not matched with the above.
-- `show` converts a Number to a String

explainException mcause epc mtval =
  "Unknown Exception: mcause=" <> show mcause <> ", epc=" <> epc <> ", mtval=" <> mtval
```

Which looks like a tidy bunch of __Explain Rules__. (Similar to Prolog!)

This thing about PureScript looks totally alien...

```purescript
-- Declare the Function Type. We can actually erase it, VSCode PureScript Extension will helpfully suggest it for us.

explainException ::
  Int        -- MCAUSE: Cause of Exception
  -> String  -- EPC: Exception Program Counter
  -> String  -- MTVAL: Exception Value
  -> String  -- Returns the Exception Explanation
```

But it works like a __Function Declaration__ in C.

[(__VSCode__ will generate the __Function Type__)](TODO)

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

Our JavaScript will call PureScript the (yummy) [__Curried Way__](https://en.wikipedia.org/wiki/Partial_application).

(Because PureScript is a Functional Language)

![PureScript looks like a neat way to express our NuttX Troubleshooting Skills as high-level rules](https://lupyuen.github.io/images/purescript-explain.png)

_Why PureScript? Could've done all this in JavaScript..._

PureScript looks like a neat way to express our __NuttX Troubleshooting Skills__ as high-level rules...

Without getting stuck with the low-level procedural plumbing of JavaScript.

Let's do a bit more PureScript...

# Parse the RISC-V Exception

_How did we get the RISC-V Exception? MCAUSE, EPC, MTVAL?_

We extracted the __RISC-V Exception__ from the NuttX Log...

```yaml
riscv_exception:
  EXCEPTION: Load page fault.
  MCAUSE:    000000000000000d,
  EPC:       000000008000a0e4,
  MTVAL:     0000000880203b88
```

PureScript really shines for __Parsing Text Strings__. We walk through the steps: [Main.purs](https://github.com/lupyuen/nuttx-purescript-parser/blob/main/src/Main.purs#L127-L191)

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

We're about to create a __PureScript String Parser__ that will accept a printed RISC-V Exception and return the MCAUSE, EPC and MTVAL.

[(__VSCode__ will generate the __Function Type__)](TODO)

This is how we write our __Parsing Function__...

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

As promised, meet our alien symbols...

- __`void`__ means ignore the text

- __`$` `something` `something`__

  is shortcut for...

  __`(` `something` `something` `)`__

- __`<*`__ is the Delimiter between Patterns

Which will skip the unnecessary prelude...

```text
riscv_exception: EXCEPTION: 
```

Next comes the __Exception Message__, which we'll capture via a __Regular Expression__...

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

And it works great with our [__RISC-V Exception Explainer__](TODO)!

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

TODO: [__Parse Stack Dump__](TODO)

# Pass NuttX Logs to PureScript

_PureScript will parse our RISC-V Exceptions and explain them... How to pass our NuttX Logs to PureScript?_

We're running [__NuttX Emulator__](TODO) inside our Web Browser.

We __intercept all logs__ emitted by the Emulator, with this JavaScript: [term.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/term.js#L487-L511)

```javascript
// When NuttX Emulator prints something
// to the Terminal Output...
Term.prototype.write = function(str) {

  // Send it to our NuttX Log Parser
  parseLog(str);
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

  // Explain the Exception and
  // link to the Disassembly
  const epc   = disassemble(exception.epc);
  const mtval = disassemble(exception.mtval);
  const exception_str = [
    "Exception:" + "&nbsp;".repeat(1) + exception.exception,
    "MCAUSE:"    + "&nbsp;".repeat(4) + exception.mcause,
    "EPC:"       + "&nbsp;".repeat(7) + epc,
    "MTVAL:"     + "&nbsp;".repeat(5) + mtval,
  ].join("<br>");

  // Display the Exception
  const parser_output = document.getElementById("parser_output");
  parser_output.innerHTML +=
    `<p>${exception_str}</p>`;

  // Explain the Exception
  // and display it
  const explain = explainException
    (exception.mcause)(exception.epc)(exception.mtval);
  parser_output.innerHTML +=
    `<p>${explain}</p>`
    .split(exception.epc, 2).join(epc)      // Link EPC to Disassembly
    .split(exception.mtval, 2).join(mtval)  // Link MTVAL to Disassembly
    ;
```

Which calls PureScript to __parse the RISC-V Exception__ and explain it.

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

_What's this function: disassemble?_

TODO

```javascript
// If `addr` is a valid address, return the Disassembly URL:
// <a href="disassemble.html?addr=8000a0e4" target="_blank">8000a0e4</a>
// Otherwise return `addr`
function disassemble(addr) {
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

TODO

# Explain NuttX Exception with PureScript

TODO

We explain in friendly words what the NuttX Exception means...

"NuttX crashed because it tried to read or write an Invalid Address. The Invalid Address is 8000ad8a. The code that caused this is at 8000ad8a. Check the NuttX Disassembly for the Source Code of the crashing line."

Here's how we explain the NuttX Exception in PureScript: [src/Main.purs](src/Main.purs)

```purescript
-- Given this NuttX Exception: `riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000008000ad8a, MTVAL: 000000008000ad8a`
-- Explain in friendly words: "NuttX stopped because it tried to read or write an Invalid Address. The Invalid Address is 8000ad8a. The code that caused this is at 8000ad8a. Check the NuttX Disassembly for the Source Code of the crashing line."
-- The next line declares the Function Type. We can actually erase it, VSCode PureScript Extension will helpfully suggest it for us.
explainException ∷ Int → String → String → String

-- Explain the NuttX Exception with mcause 12
explainException 12 epc mtval =
  "Instruction Page Fault at " <> epc <> ", " <> mtval

-- Explain the Other NuttX Exceptions, that are not matched with the above
explainException mcause epc mtval =
  "Unknown Exception: mcause=" <> show mcause <> ", epc=" <> epc <> ", mtval=" <> mtval
```

We can run it in Web Browser JavaScript: [index.html](index.html)

```javascript
  // Run explainException
  const result2 = explainException(12)('000000008000ad8a')('000000008000ad8a')
  console.log({result2});
```

Which shows...

```json
{
    "result2": "Instruction Page Fault at 000000008000ad8a, 000000008000ad8a"
}
```

# Rewrite JavaScript generated by PureScript

TODO

In the JavaScript generated by PureScript, we point the PureScript Imports to compile.purescript.org, so we don't need to deploy the imports: [run.sh](run.sh)

```bash
## Change:
##   import { main, doBoth, doRunParser, parseCSV, exampleContent2, parseException, parseStackDump, explainException } from './output/Main/index.js';
## To:
##   import { main, doBoth, doRunParser, parseCSV, exampleContent2, parseException, parseStackDump, explainException } from './index.js';
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

Try it here: https://lupyuen.github.io/nuttx-purescript-parser/

# Call PureScript from NuttX Emulator

TODO

After rewriting the JavaScript Imports, we may now call PureScript from NuttX Emulator: [index.html](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/index.html#L31-L98)

```html
<script type=module>
  // Import Main Module
  import { main, doBoth, doRunParser, parseCSV, exampleContent2, parseException, parseStackDump, explainException } from 'https://lupyuen.github.io/nuttx-purescript-parser/index.js';
  import * as StringParser_Parser from "https://compile.purescript.org/output/StringParser.Parser/index.js";

  // Run parseException
  console.log('Running parseException...');
  const exception = `riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000008000ad8a, MTVAL: 000000008000ad8a`
  const result1 = StringParser_Parser
    .runParser
    (parseException)
    (exception)
    ;
  console.log({result1});

  // Run explainException
  const result2 = explainException(12)('000000008000ad8a')('000000008000ad8a')
  console.log({result2});

  // Run parseStackDump
  console.log('Running parseStackDump...');
  const stackDump = `[    6.242000] stack_dump: 0xc02027e0: c0202010 00000000 00000001 00000000 00000000 00000000 8000ad8a 00000000`;
  const result3 = StringParser_Parser
    .runParser
    (parseStackDump)
    (stackDump)
    ;
  console.log({result3});
</script>
```

Try it here: https://lupyuen.github.io/nuttx-tinyemu/purescript

# Parse NuttX Logs in NuttX Emulator

TODO

This is how we parse every line of Terminal Output from NuttX Emulator: [term.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/term.js#L1483-L1527)

```javascript
// When TinyEMU prints to the Terminal Output...
Term.prototype.write = function(str) {
    // Parse the output with PureScript
    parseLog(str);
    ...
}

// Parse NuttX Logs with PureScript.
// Assume `str` is a single character for Terminal Output. We accumulate the characters and parse the line.
// PureScript Parser is inited in `index.html`
function parseLog(str) {

    // Accumulate the characters into a line
    if (!window.StringParser_Parser) { return; }
    termbuf += str;
    if (termbuf.indexOf("\r") < 0) { return; }

    // Ignore all Newlines and Carriage Returns
    termbuf = termbuf
        .split("\r").join("")
        .split("\n").join("");
    // console.log({termbuf});

    // Parse the Exception
    const exception = StringParser_Parser
        .runParser(parseException)(termbuf)
        .value0;

    // Explain the Exception
    if (exception.error === undefined) {
        console.log({exception});
        const explain = explainException(exception.mcause)(exception.epc)(exception.mtval);
        console.log({explain});
    }

    // Run parseStackDump
    const stackDump = StringParser_Parser
        .runParser(parseStackDump)(termbuf)
        .value0;
    if (stackDump.error === undefined) { console.log({stackDump}); }

    // Reset the Line Buffer
    termbuf = "";
}

// Buffer the last line of the Terminal Output
let termbuf = "";
```

And it works correctly yay!

```text
"exception": {
    "exception": "Load page fault",
    "mcause": 13,
    "epc": "000000008000a0e4",
    "mtval": "0000000880203b88"
}
"explain": "Load Page Fault at 000000008000a0e4, 0000000880203b88"
```

Try it here: https://lupyuen.github.io/nuttx-tinyemu/purescript

[(Watch the Demo on YouTube)](https://youtu.be/9oBhy3P7pYc)

![Parsing Apache NuttX RTOS Logs with PureScript](https://lupyuen.github.io/images/purescript-title.png)

# Show NuttX Disassembly by Address

TODO

_Given an Exception Address like 8000ad8a, can we show the NuttX Disassembly?_

We need to chunk nuttx.S (or qjs.S) by address: nuttx-8000ad90.S, nuttx-8000ae00.S, nuttx-8000b000.S, nuttx-80010000.S. And link to the NuttX Repo Source Code.

Let's chunk [qjs.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs.S), the NuttX App Disassembly for QuickJS JavaScript Engine...

- Code Addresses are at 0x8000_0000 to 0x8006_4a28

- Spanning 277K lines of code!

We created a [NuttX Disassembly Chunker](https://github.com/lupyuen/nuttx-disassembly-chunker/blob/main/src/main.rs) that will...

- Split a huge NuttX Disassembly: [qjs.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs.S)

- Into smaller Disassembly Chunk Files: [qjs-chunk/qjs-80001000.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-80001000.S)

- So that Disassembly Address 0x8000_0000 will be located in [qjs-80001000.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-80001000.S)

- And Disassembly Address 0x8000_1000 will be located in [qjs-80002000.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk/qjs-80002000.S), ...

This is how we chunk a NuttX Disassembly from [qjs.S](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs.S) to [qjs-chunk](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/qjs-chunk)...

```bash
## Chunk NuttX Disassembly $HOME/qjs.S into
## $HOME/qjs-chunk/qjs-80001000.S
## $HOME/qjs-chunk/qjs-80002000.S
## ...

chunkpath=$HOME
chunkbase=qjs
mkdir -p $chunkpath/$chunkbase-chunk
rm -f $chunkpath/$chunkbase-chunk/*
cargo run -- $chunkpath $chunkbase
```

And this is how we display the Disassembly Chunk by Address: [disassemble.js](https://github.com/lupyuen/nuttx-tinyemu/blob/main/docs/purescript/disassemble.js)

```javascript
// Show the NuttX Disassembly for the Requested Address
// http://localhost:8000/nuttx-tinyemu/docs/purescript/disassemble.html?addr=80007028

// Show 20 lines before and after the Requested Address
const before_count = 20;
const after_count  = 20;

// Convert `nuttx/arch/risc-v/src/common/crt0.c:166`
// To `<a href="https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/crt0.c#L166">...`
// Convert `quickjs-nuttx/quickjs-libc.c:1954`
// To `<a href="https://github.com/lupyuen/quickjs-nuttx/blob/master/quickjs-libc.c#L1954">...`
const search1  = "nuttx/";
const replace1 = "https://github.com/apache/nuttx/blob/master/";
const search2  = "quickjs-nuttx/";
const replace2 = "https://github.com/lupyuen/quickjs-nuttx/blob/master/";

// Convert the Source File to Source URL
function processLine(line) {
  line = line.split("\t").join("&nbsp;&nbsp;&nbsp;&nbsp;");
  if (line.indexOf(":") < 0) { return line; }
  let url = line.split(":", 2).join("#L");

  // Search and replace Source File to Source URL
  if (line.indexOf(search1) == 0) {
    url = url.split(search1, 2).join(replace1);
  } else if (line.indexOf(search2) == 0) {
    url = url.split(search2, 2).join(replace2);
  } else {
    return line;
  }
  return `<a href="${url}" target="_blank">${line}</a>`;
}

// Fetch our Disassembly File, line by line
// https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch#processing_a_text_file_line_by_line
async function* makeTextFileLineIterator(fileURL) {
  const utf8Decoder = new TextDecoder("utf-8");
  const response = await fetch(fileURL);
  const reader = response.body.getReader();
  let { value: chunk, done: readerDone } = await reader.read();
  chunk = chunk ? utf8Decoder.decode(chunk) : "";

  const newline = /\r?\n/gm;
  let startIndex = 0;
  let result;

  while (true) {
    const result = newline.exec(chunk);
    if (!result) {
      if (readerDone) break;
      const remainder = chunk.substr(startIndex);
      ({ value: chunk, done: readerDone } = await reader.read());
      chunk = remainder + (chunk ? utf8Decoder.decode(chunk) : "");
      startIndex = newline.lastIndex = 0;
      continue;
    }
    yield chunk.substring(startIndex, result.index);
    startIndex = newline.lastIndex;
  }

  if (startIndex < chunk.length) {
    // Last line didn't end in a newline char
    yield chunk.substr(startIndex);
  }
}

// Fetch and display our Disassembly File, line by line
async function run() {

  // Set the Title. `addr` is `80007028`
  const addr = new URL(document.URL).searchParams.get("addr");
  const title = document.getElementById("title");
  title.innerHTML += 
    addr.substring(0, 4).toUpperCase()
    + "_"
    + addr.substring(4).toUpperCase();

  // URL of our Disassembly File, chunked for easier display.
  // TODO: Given an Exception Address like 8000ad8a. we should try multiple files by address:
  // qjs-8000ad90.S, qjs-8000ae00.S, qjs-8000b000.S, qjs-80010000.S
  const url = "qjs-chunk/qjs-80008000.S";

  // Remember the lines before and after the Requested Address
  const before_lines = [];
  const after_lines = [];
  let linenum = 0;

  // Process our Disassembly File, line by line
  const iter = makeTextFileLineIterator(url);
  for await (const line1 of iter) {
    if (after_lines.length == 0) { linenum++; }

    // Look for the Requested Address
    if (line1.indexOf(`    ${addr}:`) == 0) {
      const line2 = processLine(line1);
      after_lines.push(line2);
      continue;
    }

    // Save the lines before the Requested Address
    const line2 = processLine(line1);
    if (after_lines.length == 0) {
      before_lines.push(line2);
      if (before_lines.length > before_count) { before_lines.shift(); }  
    } else {
      // Save the lines after the Requested Address
      after_lines.push(line2);
      if (after_lines.length > after_count) { break; }
    }
  }

  // Requested Line is `after_lines[0]`.
  // Show the Before and After Lines.
  const line = after_lines[0];
  after_lines.shift();
  console.log({before_lines});
  console.log({line});
  console.log({after_lines});

  const disassembly = document.getElementById("disassembly");
  const file = `https://github.com/lupyuen/nuttx-tinyemu/tree/main/docs/purescript/${url}#L${linenum}`;
  disassembly.innerHTML = [
    `<p><a href=${file}>(See the Disassembly File)</a></p>`,
    before_lines.join("<br>"),
    `<span id="highlight"><br>${line}<br></span>`,
    after_lines.join("<br>"),
    `<p><a href=${file}>(See the Disassembly File)</a></p>`,
  ].join("<br>");
}

run();
```

Try it here: https://lupyuen.github.io/nuttx-tinyemu/purescript/disassemble.html?addr=8000702a

![NuttX Disassembly](https://lupyuen.github.io/images/purescript-disassembly.png)

# Identify a NuttX Address

TODO

_Given a NuttX Address like 80007028: How will we know whether it's in NuttX Kernel or NuttX Apps? And whether it's Code, Data, BSS or Heap?_

This is how we identify a NuttX Address in PureScript: [src/Main.purs](src/Main.purs)

```purescript
-- Given an Address, identify the Origin (NuttX Kernel or App) and Type (Code / Data / BSS / Heap)
identifyAddress ∷ String → Maybe { origin ∷ String , type ∷ AddressType }

-- Address 502xxxxx comes from NuttX Kernel Code
-- Address 800xxxxx comes from NuttX App Code (QuickJS)
-- `|` works like `if ... else if`
-- "a `matches` b" is same as "(matches a b)"
-- `Just` returns an OK Value. `Nothing` returns No Value.
identifyAddress addr
  | "502....." `matches` addr = Just { origin: "nuttx", type: Code }
  | "800....." `matches` addr = Just { origin: "qjs",   type: Code }
  | otherwise = Nothing

-- Address can point to Code, Data, BSS or Heap
data AddressType = Code | Data | BSS | Heap

-- How to display an Address Type
instance Show AddressType where
  show Code = "Code"
  show Data = "Data"
  show BSS  = "BSS"
  show Heap = "Heap"

-- Return True if the Address matches the Regex Pattern.
-- Pattern is assumed to match the Entire Address.
matches ∷ String → String → Boolean

-- Match the Begin `^` and End `$` of the Address
-- `<>` will concat 2 strings
-- "a `unsafeRegex` b" is same as "(unsafeRegex a b)"
matches pattern addr = 
  let 
    patternWrap = "^" <> pattern <> "$"
  in
    isJust $                            -- Is there a Match...
      patternWrap `unsafeRegex` noFlags -- For our Regex Pattern (no special flags)
        `match` addr                    -- Against the Address?

-- Test our code. Parse the NuttX Exception and NuttX Stack Dump. Explain the NuttX Exception.
-- `Effect` says that it will do Side Effects (printing to console)
-- `Unit` means that no value will be returned
-- The next line declares the Function Type. We can actually erase it, VSCode PureScript Extension will helpfully suggest it for us.
printResults :: Effect Unit
printResults = do

  -- NuttX Kernel: 0x5020_0000 to 0x5021_98ac
  -- NuttX App (qjs): 0x8000_0000 to 0x8006_4a28
  logShow $ identifyAddress "502198ac" -- (Just { origin: "nuttx", type: Code })
  logShow $ identifyAddress "8000a0e4" -- (Just { origin: "qjs", type: Code })
  logShow $ identifyAddress "0000000800203b88" -- Nothing
```

_Tsk tsk so much Hard Coding..._

Our Rules are still evolving, we're not sure how the NuttX Log Parser will be used in future.

That's why we need a PureScript Editor that will allow the Rules to be tweaked easily for other platforms...

# PureScript Editor for NuttX

TODO

_How to build a PureScript Editor that will allow the Rules to be tweaked easily for other platforms?_

To run our PureScript Editor for NuttX...

```bash
git clone https://github.com/lupyuen/nuttx-trypurescript
cd nuttx-trypurescript
cd client

## Build and Test Locally:
npm install
## Produces `output` folder
## And `public/js/index.js`
npm run serve:production
## Test at http://127.0.0.1:8080

## Deploy to GitHub Pages:
rm -r ../docs
cp -r public ../docs
simple-http-server .. &
## Test at http://0.0.0.0:8000/docs/index.html

## If we need `client.js` bundle:
## npm run build:production
```

Try it here: https://lupyuen.github.io/nuttx-trypurescript

Copy [src/Main.purs](src/Main.purs) to the PureScript Editor.

```purescript
main :: Effect Unit
main = printResults
```

To this...

```purescript
import TryPureScript (render, withConsole)

main :: Effect Unit
main = render =<< withConsole do
  printResults
```

Our NuttX Parser Output appears...

```text
Instruction Page Fault at epc, mtval
Unknown Exception: mcause=0, epc=epc, mtval=mtval
(runParser) Parsing content with 'parseException'
Result: { epc: "000000008000ad8a", exception: "Instruction page fault", mcause: 12, mtval: "000000008000ad8a" }
-----
(runParser) Parsing content with 'parseStackDump'
Result: { addr: "c02027e0", timestamp: "6.242000", v1: "c0202010", v2: "00000000", v3: "00000001", v4: "00000000", v5: "00000000", v6: "00000000", v7: "8000ad8a", v8: "00000000" }
-----
```

The Generated Web Browser JavaScript looks like this...

```html
<script type="module">
import * as Control_Alt from "https://compile.purescript.org/output/Control.Alt/index.js";
import * as Control_Applicative from "https://compile.purescript.org/output/Control.Applicative/index.js";
import * as Control_Apply from "https://compile.purescript.org/output/Control.Apply/index.js";
...
var bind = /* #__PURE__ */ Control_Bind.bind(StringParser_Parser.bindParser);
var alt = /* #__PURE__ */ Control_Alt.alt(StringParser_Parser.altParser);
var voidRight = /* #__PURE__ */ Data_Functor.voidRight(StringParser_Parser.functorParser);
...
```

TODO: Where is Main Function?

TODO: Copy Generated JavaScript to NuttX Emulator

# BigInt in PureScript

TODO

_Why are we passing addresses in Text instead of Numbers? Like `8000ad8a`_

That's because 0x8000ad8a is too big for PureScript Int, a signed 32-bit integer. PureScript Int is meant to interoperate with JavaScript Integer, which is also 32-bit.

_What about PureScript BigInt?_

```bash
spago install bigints
npm install big-integer
```

If we use [PureScript BigInt](https://pursuit.purescript.org/packages/purescript-bigints/7.0.1/docs/Data.BigInt#t:BigInt), then we need NPM big-integer.

But NPM big-integer won't run inside a Web Browser with Plain Old JavaScript. That's why we're passing addresses as Strings instead of Numbers.

# Run parseCSV in Node.js

TODO

Let's run [parseCSV](https://github.com/purescript-contrib/purescript-string-parsers/blob/main/test/Examples.purs) in Node.js. Normally we run PureScript like this...

```bash
spago run
```

This is how we run it in Node.js...

```bash
$ spago build
$ node .spago/run.js

### Example Content 1 ###
(runParser) Parsing content with 'fail'
{ error: "example failure message", pos: 0 }
-----
(unParser) Parsing content with 'fail'
Position: 0
Error: "example failure message"
-----
(runParser) Parsing content with 'numberOfAs'
Result was: 6
-----
(unParser) Parsing content with 'numberOfAs'
Result was: 6
Suffix was: { position: 59, substring: "" }
-----
(runParser) Parsing content with 'removePunctuation'
Result was: "How many as are in this sentence you ask Not that many"
-----
(unParser) Parsing content with 'removePunctuation'
Result was: "How many as are in this sentence you ask Not that many"
Suffix was: { position: 59, substring: "" }
-----
(runParser) Parsing content with 'replaceVowelsWithUnderscore'
Result was: "H_w m_ny '_'s _r_ _n th_s s_nt_nc_, y__ _sk? N_t th_t m_ny."
-----
(unParser) Parsing content with 'replaceVowelsWithUnderscore'
Result was: "H_w m_ny '_'s _r_ _n th_s s_nt_nc_, y__ _sk? N_t th_t m_ny."
Suffix was: { position: 59, substring: "" }
-----
(runParser) Parsing content with 'tokenizeContentBySpaceChars'
Result was: (NonEmptyList (NonEmpty "How" ("many" : "'a's" : "are" : "in" : "this" : "sentence," : "you" : "ask?" : "Not" : "that" : "many." : Nil)))
-----
(unParser) Parsing content with 'tokenizeContentBySpaceChars'
Result was: (NonEmptyList (NonEmpty "How" ("many" : "'a's" : "are" : "in" : "this" : "sentence," : "you" : "ask?" : "Not" : "that" : "many." : Nil)))
Suffix was: { position: 59, substring: "" }
-----
(runParser) Parsing content with 'extractWords'
Result was: (NonEmptyList (NonEmpty "How" ("many" : "a" : "s" : "are" : "in" : "this" : "sentence" : "you" : "ask" : "Not" : "that" : "many" : Nil)))
-----
(unParser) Parsing content with 'extractWords'
Result was: (NonEmptyList (NonEmpty "How" ("many" : "a" : "s" : "are" : "in" : "this" : "sentence" : "you" : "ask" : "Not" : "that" : "many" : Nil)))
Suffix was: { position: 59, substring: "" }
-----
(runParser) Parsing content with 'badExtractWords'
{ error: "Could not find a character that separated the content...", pos: 43 }
-----
(unParser) Parsing content with 'badExtractWords'
Position: 43
Error: "Could not find a character that separated the content..."
-----
(runParser) Parsing content with 'quotedLetterExists'
Result was: true
-----
(unParser) Parsing content with 'quotedLetterExists'
Result was: true
Suffix was: { position: 59, substring: "" }
-----

### Example Content 2 ###
(runParser) Parsing content with 'parseCSV'
Result was: { age: "24", firstName: "Mark", idNumber: "523", lastName: "Kenderson", modifiedEmail: "mynameismark@mark.mark.com", originalEmail: "my.name.is.mark@mark.mark.com" }
-----
(unParser) Parsing content with 'parseCSV'
Result was: { age: "24", firstName: "Mark", idNumber: "523", lastName: "Kenderson", modifiedEmail: "mynameismark@mark.mark.com", originalEmail: "my.name.is.mark@mark.mark.com" }
Suffix was: { position: 110, substring: "" }
-----
```

# Run parseCSV in Web Browser

TODO

Here's how we run [parseCSV](https://github.com/purescript-contrib/purescript-string-parsers/blob/main/test/Examples.purs) in the Web Browser: [index.html](index.html)

```javascript
  // Import Main Module
  import { main, doBoth, doRunParser, parseCSV, exampleContent2 } from './output/Main/index.js';
  import * as StringParser_Parser from "./output/StringParser.Parser/index.js";

  // Run parseCSV
  const result = StringParser_Parser
    .runParser
    (parseCSV)
    (exampleContent2)
    ;
  console.log({result});
```

Output:

```json
{
    "result": {
        "value0": {
            "idNumber": "523",
            "firstName": "Mark",
            "lastName": "Kenderson",
            "age": "24",
            "originalEmail": "my.name.is.mark@mark.mark.com",
            "modifiedEmail": "mynameismark@mark.mark.com"
        }
    }
}
```

We expose the PureScript Functions in the Web Browser: [index.html](index.html)

```javascript
// Import Main Module
import { main, doBoth, doRunParser, parseCSV, exampleContent2 } from './output/Main/index.js';
import * as StringParser_Parser from "./output/StringParser.Parser/index.js";

// For Testing: Export the PureScript Functions
window.main = main;
window.doBoth = doBoth;
window.doRunParser = doRunParser;
window.parseCSV = parseCSV;
window.exampleContent2 = exampleContent2;
window.StringParser_Parser = StringParser_Parser;
```

So we can run experiments in the JavaScript Console...

```javascript
// Run parseCSV in JavaScript Console
window.StringParser_Parser
  .runParser
  (window.parseCSV)
  (window.exampleContent2)
```

# Run parseCSV in try.purescript.org

TODO

To run [parseCSV](https://github.com/purescript-contrib/purescript-string-parsers/blob/main/test/Examples.purs) at [try.purescript.org](https://try.purescript.org/), change...

```purescript
main :: Effect Unit
main = printResults
```

To this...

```purescript
import TryPureScript (render, withConsole)

main :: Effect Unit
main = render =<< withConsole do
  printResults
```

# Compile PureScript to JavaScript in Web Browser

TODO

Here's how we compile PureScript to JavaScript inside our Web Browser...

https://github.com/lupyuen/nuttx-tinyemu/blob/fc22c9fba2d6fbc4faf8c1fb02f4761952cb66cd/docs/blockly/jslinux.js#L755-L804

```javascript
// Compile PureScript to JavaScript
// Maybe we'll run a PureScript to analyse the Real-Time Logs from a NuttX Device?
// https://lupyuen.github.io/nuttx-tinyemu/blockly/
async function compile_purescript() {

    // Public Server API that compiles PureScript to JavaScript
    // https://github.com/purescript/trypurescript#server-api
    const url = "https://compile.purescript.org/compile";
    const contentType = "text/plain;charset=UTF-8";

    // PureScript to be compiled to JavaScript
    const body =
`
module Main where

import Prelude

import Effect (Effect)
import Effect.Console (log)
import Data.Array ((..))
import Data.Foldable (for_)
import TryPureScript (render, withConsole)

main :: Effect Unit
main = render =<< withConsole do
  for_ (10 .. 1) \\n -> log (show n <> "...")
  log "Lift off!"
`;

    // Call Public Server API to compile our PureScript to JavaScript
    // Default options are marked with *
    // https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch
    const response = await fetch(url, {
        method: "POST", // *GET, POST, PUT, DELETE, etc.
        mode: "cors", // no-cors, *cors, same-origin
        cache: "no-cache", // *default, no-cache, reload, force-cache, only-if-cached
        credentials: "same-origin", // include, *same-origin, omit
        headers: { "Content-Type": contentType },
        redirect: "follow", // manual, *follow, error
        referrerPolicy: "no-referrer", // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
        body: body,
    });

    // Print the response
    // { "js": "import * as Control_Bind from \"../Control.Bind/index.js\";\nimport * as Data_Array from \"../Data.Array/index.js\";\nimport * as Data_Foldable from \"../Data.Foldable/index.js\";\nimport * as Data_Show from \"../Data.Show/index.js\";\nimport * as Effect from \"../Effect/index.js\";\nimport * as Effect_Console from \"../Effect.Console/index.js\";\nimport * as TryPureScript from \"../TryPureScript/index.js\";\nvar show = /* #__PURE__ */ Data_Show.show(Data_Show.showInt);\nvar main = /* #__PURE__ */ Control_Bind.bindFlipped(Effect.bindEffect)(TryPureScript.render)(/* #__PURE__ */ TryPureScript.withConsole(function __do() {\n    Data_Foldable.for_(Effect.applicativeEffect)(Data_Foldable.foldableArray)(Data_Array.range(10)(1))(function (n) {\n        return Effect_Console.log(show(n) + \"...\");\n    })();\n    return Effect_Console.log(\"Lift off!\")();\n}));\nexport {\n    main\n};",
    //   "warnings": [] }
    console.log(await response.json());
}
```

The JSON Response looks like this...

```text
{
  "js": "
    import * as Control_Bind from "../Control.Bind/index.js";
    import * as Data_Array from "../Data.Array/index.js";
    import * as Data_Foldable from "../Data.Foldable/index.js";
    import * as Data_Show from "../Data.Show/index.js";
    import * as Effect from "../Effect/index.js";
    import * as Effect_Console from "../Effect.Console/index.js";
    import * as TryPureScript from "../TryPureScript/index.js";
    var show = /* #__PURE__ */ Data_Show.show(Data_Show.showInt);
    var main = /* #__PURE__ */ Control_Bind.bindFlipped(Effect.bindEffect)(TryPureScript.render)(/* #__PURE__ */ TryPureScript.withConsole(function __do() {
          Data_Foldable.for_(Effect.applicativeEffect)(Data_Foldable.foldableArray)(Data_Array.range(10)(1))(function (n) {
              return Effect_Console.log(show(n) + "...");
        })();
        return Effect_Console.log("Lift off!")();
    }));
    export {
          main
    };
  ",
  "warnings": []
}
```

# Parsing Apache NuttX RTOS Logs with PureScript

TODO

In the Web Browser, we can get Real-Time Logs from NuttX Devices (Web Serial API) NuttX Emulator (Term.js)...

What if we could Analyse the NuttX Logs in Real-Time? And show the results in the Web Browser?

Like for [Stack Dumps](https://gist.github.com/lupyuen/a715e4e77c011d610d0b418e97f8bf5d#file-nuttx-tcc-app-log-L168-L224), [ELF Loader Log](https://gist.github.com/lupyuen/a715e4e77c011d610d0b418e97f8bf5d#file-nuttx-tcc-app-log-L1-L167), [Memory Manager Log](https://docs.google.com/spreadsheets/d/1g0-O2qdgjwNfSIxfayNzpUN8mmMyWFmRf2dMyQ9a8JI/edit#gid=0) (malloc / free)?

Let's do it with PureScript, since Functional Languages are better for Parsing Text.

And we'll support Online Scripting of our PureScript for Log Parsing, similar to [try.purescript.org](https://try.purescript.org/)

(Also automate the [Stack Dump Analysis](https://nuttx.apache.org/docs/latest/guides/cortexmhardfaults.html#))

(Here's a [NuttX Emulator that crashes](https://lupyuen.github.io/nuttx-tinyemu/purescript/). Guess why?)

_Why not code all this in JavaScript instead of PureScript?_

(1) NuttX Logs might appear differently over time. Good to have a quick way to patch our parser as the NuttX Logs change.

(2) We need to implement high-level Declarative Rules that will interpret the parsed NuttX Logs. We might adjust the Rules over time.

(FYI Parsing CSV in JavaScript [looks like this](https://github.com/Chevrotain/chevrotain/blob/master/examples/grammars/csv/csv.js))

_Why PureScript instead of Haskell?_

Right now our NuttX Logs are accessible in a Web Browser through JavaScript: NuttX Emulator (over WebAssembly) and NuttX Device (over Web Serial API).

PureScript is probably easier to run in a Web Browser for processing the JavaScript Logs.

[(Zephyr Stack Dumps are also complicated)](https://github.com/zephyrproject-rtos/zephyr/issues/4416)

# What's Next

TODO

```bash
git clone TODO
cd TODO
code .
## Open src/main TODO
```

Install vscode extension 

It's 2024... Surely there's a better way to grok the log?
Stack trace / mm log / elf loader 

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/purescript.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/purescript.md)
