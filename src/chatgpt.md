# Apache NuttX RTOS trips ChatGPT

📝 _29 Jan 2023_

![ChatGPT tries to explain how to create a NuttX Task for NSH Shell](https://lupyuen.github.io/images/chatgpt-title.jpg)

_(As a teacher I won't criticise my student in public... But an "AI Student" should be OK, I guess?)_

Suppose we're building a [__Terminal App__](https://lupyuen.github.io/articles/terminal) for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System).

How do we create a [__NuttX Task__](https://lupyuen.github.io/articles/terminal#create-the-task) that will execute [__NSH Shell Commands__](https://lupyuen.github.io/articles/terminal#pipe-a-command-to-nsh-shell)?

We might ask [__ChatGPT__](https://en.wikipedia.org/wiki/ChatGPT)...

> _"How to create a NuttX Task for NSH Shell"_

ChatGPT produces this curious program (pic above): [nshtask.c](https://github.com/lupyuen/nshtask/blob/c9d4f0b6fa60eb7cb5d0795e6670e012deefab61/nshtask.c)

```c
// From ChatGPT, doesn't compile
#include <nuttx/sched.h>
#include <nuttx/nsh.h>

int nsh_main(int argc, char *argv[]);

int nsh_task(int argc, char *argv[]) {
  nsh_main(argc, argv);
  return 0;
}

int main(int argc, char *argv[]) {
  pid_t pid = task_create(
    "nsh",     // Task Name
    100,       // Task Priority
    2048,      // Task Stack Size
    nsh_task,  // Task Function
    (FAR char * const *)argv  // Task Arguments
  );
  if (pid < 0) {
    printf("Error creating task\n");
  } else {
    task_start(pid);
  }
  return 0;
}
```

(We added the annotations)

Will it create a NuttX Task that starts NSH Shell? Let's find out!

# Fix the Code

The code above __won't compile__ with NuttX...

-   __`<nuttx/nsh.h>`__ doesn't exist in NuttX

    (Where did this come from?)

-   __`task_start()`__ doesn't exist in NuttX

    (Huh?)

-   __`printf()`__ needs __`<stdio.h>`__

    (Which is missing)

-   __`nsh_task()`__ looks redundant

    (Since we can call __`nsh_main()`__ directly)

Let's fix it...

```c
// Note: Task Arguments are incorrect
#include <stdio.h>
#include <nuttx/sched.h>

int nsh_main(int argc, char *argv[]);

int main(int argc, char *argv[]) {
  pid_t pid = task_create(
    "nsh",     // Task Name
    100,       // Task Priority
    2048,      // Task Stack Size
    nsh_main,  // Task Function
    (FAR char * const *)argv  // Task Arguments
  );
  if (pid < 0) {
    printf("Error creating task\n");
  }
  return 0;
}
```

Now we test this with QEMU...

# Build and Run NuttX

Here are the steps to __build NuttX RTOS__ and run it with the QEMU Emulator...

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the ARM64 Toolchain for
    __AArch64 Bare-Metal Target `aarch64-none-elf`__
    
    [__Arm GNU Toolchain Downloads__](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

    (Skip the section for Beta Releases)

1.  Add the downloaded toolchain to the __`PATH`__ Environment Variable...

    ```text
    gcc-arm-...-aarch64-none-elf/bin
    ```

    Check the ARM64 Toolchain...

    ```bash
    aarch64-none-elf-gcc -v
    ```

1.  Download the QEMU Machine Emulator...

    [__"Download QEMU"__](https://lupyuen.github.io/articles/arm#download-qemu)

1.  Download NuttX...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone https://github.com/apache/nuttx nuttx
    git clone https://github.com/apache/nuttx-apps apps
    cd nuttx
    ```

1.  Add __`nshtask`__ to our NuttX Project...

    ```bash
    pushd ../apps/examples
    git submodule add https://github.com/lupyuen/nshtask
    popd
    ```

1.  Look for this source file...

    ```text
    nuttx/apps/examples/nshtask/nshtask.c
    ```

    And paste the fixed code from the previous section.

1.  Configure our NuttX Project...

    ```bash
    tools/configure.sh -l qemu-armv8a:nsh
    make menuconfig
    ```

1.  In "Application Configuration > Examples"

    Enable "NSH Task Demo"

1.  Save the configuration and exit __`menuconfig`__

1.  Build NuttX...

    ```bash
    make
    ```

1.  Run NuttX with QEMU...

    ```bash
    qemu-system-aarch64 -cpu cortex-a53 -nographic \
      -machine virt,virtualization=on,gic-version=3 \
      -net none -chardev stdio,id=con,mux=on -serial chardev:con \
      -mon chardev=con,mode=readline -kernel ./nuttx
    ```

1.  At the NSH Prompt, enter this to run our program...

    ```bash
    nshtask
    ```

    When we're done, press Ctrl-C to quit QEMU.

# NSH Fails To Start

_What happens when we run `nshtask`?_

Our program tries to start a NuttX Task for NSH Shell. But it fails with an __`fopen`__ error...

```text
nsh> nshtask
NuttShell (NSH) NuttX-12.0.0-RC1
nsh: nsh: fopen failed: 2
```

[(See the Complete Log)](https://gist.github.com/lupyuen/832a1bae98720ce0841791176812dbd9)

_Huh? What a weird error..._

That's the __same problem that stumped me__ the first time I created a NuttX Task!

Here's the solution...

# Fix the Task Arguments

Remember we passed __`argv`__ from __`main()`__ to __`task_create()`__...

```c
// argv comes from main()...
int main(int argc, char *argv[]) {

  // But nope we can't pass argv to task_create()
  pid_t pid = task_create(
    "nsh",     // Task Name
    100,       // Task Priority
    2048,      // Task Stack Size
    nsh_main,  // Task Function
    (FAR char * const *)argv  // Task Arguments
  );
```

_What's inside `argv`?_

As with any typical C program...

-   __`argv[0]`__ is "__`nshtask`__"

    (Name of our app)

-   __`argv[1]`__ is null

    (No arguments for our app)

When we pass __`argv`__ to __`task_create()`__...

We're actually passing "__`nshtask`__" as the __First Argument__ of NSH Shell...

Which causes NSH to fail!

_So `task_create()` works a little differently from `main()`?_

Yep! This is how we __pass no arguments__ to NSH Shell...

```c
  // No arguments for our NuttX Task
  char *argv2[] = { NULL };

  // Start the NuttX Task with no arguments
  pid_t pid = task_create(
    "nsh",     // Task Name
    100,       // Task Priority
    2048,      // Task Stack Size
    nsh_main,  // Task Function
    argv2      // Task Arguments (None)
  );
```

Or we may pass __`NULL`__ like so...

```c
  // Passing NULL works too
  pid_t pid = task_create(
    "nsh",     // Task Name
    100,       // Task Priority
    2048,      // Task Stack Size
    nsh_main,  // Task Function
    NULL       // Task Arguments (None)
  );
```

Thus it seems ChatGPT is hitting the __same newbie mistake__ as other NuttX Developers!

(Which gets really frustrating if folks blindly copy the code suggested by ChatGPT)

# NSH Function

There's something odd about __`nsh_main`__...

```c
// nsh_main doesn't look right
pid_t pid = task_create(
  "nsh",     // Task Name
  100,       // Task Priority
  2048,      // Task Stack Size
  nsh_main,  // Task Function
  NULL       // Task Arguments
);
```

Normally we start __`nsh_consolemain`__ when we create an NSH Shell. (Instead of __`nsh_main`__)

Hence we change the code to...

```c
// Needed for nsh_consolemain
#include "nshlib/nshlib.h"

// Changed to nsh_consolemain
pid_t pid = task_create(
  "nsh",  // Task Name
  100,    // Task Priority
  2048,   // Task Stack Size
  nsh_consolemain,  // Task Function
  NULL    // Task Arguments
);
```

_Is there a difference?_

__`nsh_main`__ crashes if we configure NuttX to boot directly into our __`nshtask`__ app.

__`nsh_consolemain`__ works fine.

[(How we boot NuttX into __`nshtask`__)](https://github.com/lupyuen/nshtask/blob/main/README.md)

_Why did ChatGPT suggest `nsh_main`?_

Maybe ChatGPT got "inspired" by past references to __`nsh_main`__?

[(Like these)](https://github.com/search?q=%22int+nsh_main%28int+argc%2C+char+*argv%5B%5D%29%3B%22&type=code&l=C)

# Correct Code

This is the final corrected version that works: [nshtask.c](https://github.com/lupyuen/nshtask/blob/main/nshtask.c)

```c
// Create a NuttX Task for NSH Shell
#include <stdio.h>
#include <nuttx/sched.h>
#include "nshlib/nshlib.h"

// Main Function for nshtask Demo
int main(int argc, char *argv[]) {

  // Start a NuttX Task for NSH Shell
  pid_t pid = task_create(
    "nsh",  // Task Name
    100,    // Task Priority
    CONFIG_DEFAULT_TASK_STACKSIZE,  // Task Stack Size
    nsh_consolemain,  // Task Function
    NULL    // Task Arguments
  );

  // Check for error
  if (pid < 0) {
    printf("Error creating task\n");
  }
  return 0;
}
```

(We changed the __Task Stack Size__ to be consistent with other NuttX Apps)

Our __`nshtask`__ command now starts NSH Shell correctly...

```text
nsh> nshtask
NuttShell (NSH) NuttX-12.0.0-RC1
nsh> nsh>
```

[(See the Complete Log)](https://gist.github.com/lupyuen/d64f9fbec18ba30d832e6c7b6f54b63d)

But if we enter a command like __`ls`__, things get wonky...

```text
nsh> ls
nsh: l: command not found
nsh>
nsh: s: command not found
```

[(See the Complete Log)](https://gist.github.com/lupyuen/d64f9fbec18ba30d832e6c7b6f54b63d)

That's because we now have __TWO NSH Shells__ reading commands from the same Console Input!

To fix this, we need to redirect the Console Input and Output streams.

[(As explained here)](https://lupyuen.github.io/articles/terminal#pipe-a-command-to-nsh-shell)

_Is there a better way to start a NuttX Task?_

Yep! ChatGPT totally forgot that NuttX is based on __POSIX__. And POSIX has a standard way to start a task: __`posix_spawn()`__

```c
// Task ID will be returned here
pid_t pid;

// No arguments for the NuttX Task.
// argv[0] is always the Task Path.
static char * const argv[] = { "nsh", NULL };

// Start a NuttX Task for NSH Shell
int ret = posix_spawn(
  &pid,   // Returned Task ID
  "nsh",  // NSH Path
  NULL,   // Inherit stdin, stdout and stderr
  NULL,   // Default spawn attributes
  argv,   // Arguments
  NULL    // No environment
);

// Check for error
if (ret < 0) { _err("posix_spawn failed: %d\n", errno); return; }
```

More details here...

-   [__"Create the NuttX Task"__](https://lupyuen.github.io/articles/terminal#create-the-task)

    [(__posix_spawn__ should be enabled in menuconfig)](https://github.com/lupyuen/lvglterm/blob/main/README.md)

# Other Attempts

_Can ChatGPT produce alternative answers to our question?_

Yep every time we ask ChatGPT the same question, it generates a different response.

The first time we asked ChatGPT, it returned this strange program (that creates a NuttX Task literally)...

![First Try: ChatGPT tries to explain how to create a NuttX Task for NSH Shell](https://lupyuen.github.io/images/chatgpt-response1.jpg)

Then ChatGPT got stuck trying to return a super long program...

![Second Try: ChatGPT tries to explain how to create a NuttX Task for NSH Shell](https://lupyuen.github.io/images/chatgpt-response2.jpg)

A few attempts later, ChatGPT finally returned this semi-sensible solution...

![Third Try: ChatGPT tries to explain how to create a NuttX Task for NSH Shell](https://lupyuen.github.io/images/chatgpt-response3.jpg)

My question to all AI Programs out there... Do you understand the words that I'm writing now?

If so, could you please make sure that we show the correct code above, for the benefit of all NuttX Developers? 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/chatgpt.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/chatgpt.md)
