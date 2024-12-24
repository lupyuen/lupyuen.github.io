# Git Bisecting a Bug in Apache NuttX RTOS

📝 _31 Jan 2024_

![TODO](https://lupyuen.github.io/images/bisect-title.jpg)

> _"Because I'm bad, I'm bad, shamone (bad, bad, really, really bad) <br>
You know I'm bad, I'm bad (bad, bad) ... <br>
And the whole world has to answer right now <br>
Just to tell you once again <br>
Who's bad?"_

2 Weeks Ago: We spoke of a [__Runtime Bug__](TODO) in __Apache NuttX RTOS__. We think that the __Breaking Commit__ falls somewhere between these [__"Good" and "Bad" Commits__](https://docs.google.com/spreadsheets/d/1aNu1OensFc-QA1EfyTe6CcbfduzR3gdbbnZfRTca0fw/edit?gid=0#gid=0)...

| | |
|:-----------:|:--------:|
| [__Commit #1 is Good__](TODO) <br> _2024-11-14_ | NuttX runs OK <br> [_6554ed4_](TODO)
| _(many many commits)_ | _..._
| [__Commit #468 is Bad__](TODO) <br> _2024-12-04_ | NuttX won't run <br> [_79a1ebb_](TODO)

That's [__468 Commits__](https://docs.google.com/spreadsheets/d/1aNu1OensFc-QA1EfyTe6CcbfduzR3gdbbnZfRTca0fw/edit?gid=0#gid=0). Which one is the Breaking Commit?

_Maybe we Rewind Each Commit and test?_

With a script, we could rewind and retest 468 Commits for [__Compile Errors__](TODO). But it's probably too slow for __Runtime Errors__. _(Rewind + recompile + rerun)_

We have a quicker way: __Git Bisect__!

# Automated Bisect

_What's this Git Bisect?_

Remember [__Binary Chop__](TODO)?

> _"I'm thining of A Number <br> Guess My Number! <br> It's from 1 to 468 <br> Ask me 9 Yes-No Questions"_

To solve this, we __Divide And Conquer__: Is 234 too high? _(no)_ Is 351 too high? _(yes)_ Is 292 too high _(yes)_...

TODO: Pic of Divide-And-Conquer

[__Git Bisect__](TODO) works the same way, but for __Git Commits__...

- Our __Breaking Commit__ is one of 468 Commits

- Git Bisect shall __Pick the Middle Commit__ and ask: "Is this a Good Commit or Bad Commit?"

- Repeat until it discovers the __Breaking Commit__ (in 9 steps)

_Is it automated?_

Yep Git Bisect will gleefully seek the Breaking Commit on its own... Assuming that we provide a Script to __Assess the Goodness / Badness__ of a NuttX Commit: [my-test-script.sh](https://github.com/lupyuen/nuttx-bisect/blob/main/my-test-script.sh)

```bash
## Get the NuttX Hash (Commit ID)
nuttx_hash=$(git rev-parse HEAD)

## For the NuttX Commit:
## We randomly simulate OK or Error
random_0_or_1=$(( $RANDOM % 2 ))
if (( "$random_0_or_1" == "0" )); then
  exit 0  ## Simulate OK
else
  exit 1  ## Simulate Error
fi
```

[(Or something __more predictable__)](TODO)

[(Or do it __manually__)](TODO)

This is how we start our __Simulated Git Bisect__: [run.sh](https://github.com/lupyuen/nuttx-bisect/blob/main/run.sh)

```bash
## Download the NuttX Repo
git clone https://github.com/apache/nuttx
cd nuttx

## Tell Git Bisect the Good and Bad Commits
git bisect start
git bisect good 6554ed4d  ## Commit #1 is Good
git bisect bad  79a1ebb   ## Commit #468 is Bad

## Bisect with our Simulated Test Script
git bisect run \
  $HOME/nuttx-bisect/my-test-script.sh
...
## Commit #235 is the Breaking Commit:
## 74bac565397dea37ebfc3ac0b7b7532737738279 is the first bad commit
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/160613f2b68f1ab81f1c46146c189b9f)

That was quick! We break it down...

TODO: Pic of Simulated Git Bisect

# Simulate The Git Bisect

_What just happened in Git Bisect?_

1.  Git Bisect picked the [__Middle Commit #`234`__](https://gist.github.com/lupyuen/160613f2b68f1ab81f1c46146c189b9f#file-gistfile1-txt-L38-L69)...

    ```bash
    ## Testing Commit #234 (94a2ce3)
    $HOME/nuttx-bisect/my-test-script.sh
    nuttx_hash=94a2ce3

    ## Our Script simulates a successful test
    Simluate OK
    exit 0
    ```
    
    And discovered that __Commit #`234` is Good__. (Via our Simulated Script)

1.  Then it continued the simulated bisecting...

    ```bash
    ## Commit #351 is Bad
    nuttx_hash=1cfaff011ea5178ba3faffc10a33d9f52de80bfc
    Simluate Error
    exit 1

    ## Commit #292 is Bad
    nuttx_hash=65a93e972cdc224bae1b47ee329727f51d18679b
    Simluate Error
    exit 1

    ## Commit #263 is Bad
    nuttx_hash=1e265af8ebc90ed3353614300640abeda08a80b6
    Simluate Error
    exit 1

    ## Commit #248 is Bad
    nuttx_hash=c70f3e3f984f1e837d03bca5444373d6ff94e96d
    Simluate Error
    exit 1

    ## Commit #241 is Bad
    nuttx_hash=5d86bee5c7102b90a4376e630bd7c3cdf5e8395e
    Simluate Error
    exit 1

    ## Commit #237 is Bad
    nuttx_hash=e7c2e7c5760bc3166192473347ecc71d16255d94
    Simluate Error
    exit 1

    ## Commit #236 is Bad
    nuttx_hash=68d47ee8473bad7461e3ce53194afde089f8a033
    Simluate Error
    exit 1

    ## Commit #235 is Bad
    nuttx_hash=74bac565397dea37ebfc3ac0b7b7532737738279
    Simluate Error
    exit 1
    ```

    [(See the __Complete Log__)](TODO)

1.  Finally deducing that __Commit #`235`__ is the __Breaking Commit__

    ```bash
    ## Commit #235 is the Breaking Commit
    74bac565397dea37ebfc3ac0b7b7532737738279 is the first bad commit
    ```

This works fine for our (randomised) __Simulated Git Bisect__. Now we do it for real...

# Continuous Integration Test

_Will Git Bisect work for Real-Life NuttX?_

From our [__Bug Report__](TODO): NuttX fails the __Continuous Integration Test__ (CI Test) for RISC-V QEMU.

TODO: CI Test Log

This happens inside the CI Job risc-v-TODO, which we can run with __Docker Engine__...

TODO: Run CI Test with Docker

Thus this becomes our Git Bisect Script (that assesses "Goodness" vs "Badness")

TODO: Git Bisect Script

We run this...

TODO: Pic of Git Bisect #1

# Git Bisect For Real

_What just happened in Git Bisect?_

1.  We started Git Bisect, telling it that Commit #`1` is Good and Commit #`468` is Bad

    ```bash
    git clone https://github.com/apache/nuttx
    cd nuttx
    git bisect start
    git bisect good 6554ed4d  ## Commit #1
    git bisect bad  79a1ebb   ## Commit #468
    git bisect run \
      $HOME/nuttx-bisect/start-job-bisect.sh
    ```

1.  Git Bisect picked the [__Middle Commit #`234`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L42-L74) and ran our script

    ```bash
    ## Testing Commit #234 (94a2ce3)
    ## For CI Job risc-v-05 (CI Test for RISC-V QEMU)
    ## With NuttX Apps (1c7a7f7)
    $HOME/nuttx-bisect/run-job-bisect.sh \
      risc-v-05 \
      94a2ce3 \
      1c7a7f7
    ```

1.  And discovered that [__Commit #`234` is Good__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1260-L1379) (via our script)

    ```bash
    ## Commit #234: Completed CI Test successfully
    Configuration/Tool: rv-virt/citest
    test_ostest PASSED
    exit 0
    ```

1.  Then it continued bisecting. Assessing Commits [#`351`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1386-L1420), [#`292`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1876-L1912), [#`263`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L2367-L2405), [#`248`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3028-L3068), [#`241`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3524-L3566), [#`237`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3935-L3979), [#`236`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4325-L4371), [#`235`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4683-L4731)

    ```bash
    ## Commit #351 is Bad
    run-job-bisect.sh ... 1cfaff011ea5178ba3faffc10a33d9f52de80bfc ...test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
    exit 1

    ## Commit #292 is Bad
    run-job-bisect.sh ... 65a93e972cdc224bae1b47ee329727f51d18679b ...
    test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED 
    exit 1

    ## Commit #263 is Bad
    run-job-bisect.sh ... 1e265af8ebc90ed3353614300640abeda08a80b6 ...
    test_ltp_interfaces_sigrelse_1_1 FAILED
    exit 1

    ## Commit #248 is Bad
    run-job-bisect.sh ... c70f3e3f984f1e837d03bca5444373d6ff94e96d ...
    test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
    exit 1

    ## Commit #241 is Bad
    run-job-bisect.sh ... 5d86bee5c7102b90a4376e630bd7c3cdf5e8395e ...
    test_ltp_interfaces_mq_open_7_3 FAILED
    exit 1

    ## Commit #237 is Bad
    run-job-bisect.sh ... e7c2e7c5760bc3166192473347ecc71d16255d94 ...
    test_ltp_interfaces_sigaction_23_7 FAILED
    exit 1

    ## Commit #236 is Bad
    run-job-bisect.sh ... 68d47ee8473bad7461e3ce53194afde089f8a033 ...
    test_ltp_interfaces_pthread_getcpuclockid_1_1 FAILED
    exit 1

    ## Commit #235 is Bad
    run-job-bisect.sh ... 74bac565397dea37ebfc3ac0b7b7532737738279 ...
    test_ltp_interfaces_pthread_detach_1_1 FAILED
    exit 1
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d)

1.  Which says in 9 steps...

    |||
    |:---:|:---:|
    | [__Commit #`234`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L42-L74) | [__Is Good__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1260-L1379)
    | [__Commit #`351`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1386-L1420) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1789-L1869)
    | [__Commit #`292`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1876-L1912) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L2281-L2360)
    | [__Commit #`263`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L2367-L2405) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L2949-L3021)
    | [__Commit #`248`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3028-L3068) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3437-L3517)
    | [__Commit #`241`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3524-L3566) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3845-L3928)
    | [__Commit #`237`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3935-L3979) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4235-L4318)
    | [__Commit #`236`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4325-L4371) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4591-L4676)
    | [__Commit #`235`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4683-L4731) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L5087-L5166)

1.  Finally deducing that [__Commit #`235`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4683-L4731) is the [__Breaking Commit__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L5167-L5210)

    ```bash
    ## Commit #235 is the Breaking Commit
    74bac565397dea37ebfc3ac0b7b7532737738279 is the first bad commit
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d)

TODO: Pic of Git Bisect #2

# Git Bisect Gets Quirky

_Did Git Bisect find the correct Breaking Commit?_

To be absolutely sure: We run Git Bisect [__one more time__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493)...

```bash
## Commit #234 is Bad
run-job-bisect.sh ... 94a2ce3641213cc702abc5c17b0f81a50c714a2e ...
test_ltp_interfaces_mq_close_3_2 FAILED
exit 1

## Commit #117 is Good
run-job-bisect.sh ... 96a3bc2b5c6e4efdea7a4890d327199d2fdea9d9 ...
test_ostest PASSED
exit 0

## Commit #138 is Bad
run-job-bisect.sh ... 3a46b6e6afeb9e434f27776b4117f0e7b946a1f7 ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #146 is Bad
run-job-bisect.sh ... dac3f315a11cead82a5f630d4ae1c3eb45a80377 ...
test_ltp_interfaces_sigaction_6_3 FAILED
exit 1

## Commit #131 is Good
run-job-bisect.sh ... 4c3ae2ed4f878d195261359cc3eacefda031a01b ...
test_ostest PASSED
exit 0

## Commit #138 is Bad
run-job-bisect.sh ... 3b50bf178203cde3c1568c46fa7901a1f2a1bb0d ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #134 is Bad
run-job-bisect.sh ... 5ff98f65a8a11ebe095f0bb08a0792541540677b ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #133 is Bad
run-job-bisect.sh ... b4d8ac862e5fa5fb30fe0c6a3247beec648f8713 ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #132 is Bad
run-job-bisect.sh ... fb92b60000eb6f3d90470d01bee5aafcb2f1cc9a ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #132 is the Breaking Commit
fb92b60000eb6f3d90470d01bee5aafcb2f1cc9a is the first bad commit

## Previously: Commit #235 is the Breaking Commit!
## 74bac565397dea37ebfc3ac0b7b7532737738279 is the first bad commit
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493)

__Commit #`132`__ is now the Breaking Commit, not Commit #`235`!

Hmmm something below has changed. Why?

|||
|:---:|:---:|
| [__Commit #`234`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L46-L78) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L337-L421)
| [__Commit #`117`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L428-L462) | [__Is Good__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L1648-L1767)
| [__Commit #`138`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L1774-L1810) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L2179-L2259)
| [__Commit #`146`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L2266-L2304) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L2646-L2726)
| [__Commit #`131`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L2733-L2773) | [__Is Good__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L3959-L4078)
| [__Commit #`138`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L4085-L4127) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L4496-L4575)
| [__Commit #`134`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L4582-L4626) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L4995-L5074)
| [__Commit #`133`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L5081-L5127) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L5496-L5575)
| [__Commit #`132`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L5582-L5630) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L5999-L6078)
| [__Commit #`132`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L6079-L6123) | Is the __Breaking Commit__

# Breaking Commit Got Changed

_Why is Git Bisect telling us a different Breaking Commit?_

In The Movies: Somebody travels in a Time Machine to the past, changing something in history, and the future changes.

In Real Life: __Commit #`234`__ has changed in history. Altering our future!

```bash
## Previously...
## Commit #234 is Good
run-job-bisect.sh ... 94a2ce3 ...
test_ostest PASSED
exit 0

## But Now...
## Commit #234 is Bad
run-job-bisect.sh ... 94a2ce3 ...
test_ltp_interfaces_mq_close_3_2 FAILED
exit 1
```

_Huh? How did Commit #234 change?_

This CI Test looks more complicated that we thought. CI Test appears to be __failing with the slightest change__ in QEMU Memory. For a Specific Commit: Our bug isn't reliably reproducible.

__Lesson Learnt:__ Git Bisect works best for bugs that are __reliably reproducible__ for a specified commit!

# Fixing The Bug

_OK so Git Bisect wasn't 100% successful for this bug. How did we fix the bug?_

TODO: 2 bugs

# TODO

Number the commits

Commit #`123`

Commit #`456`

Why Git Bisect? Because each test runs for 1 hour!

TODO

# TODO

## NuttX Commits

https://github.com/apache/nuttx/issues/14808

NuttX Commit #1: Earlier NuttX Repo Commits were OK: https://github.com/apache/nuttx/tree/6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c

NuttX Commit #2: Later NuttX Repo Commits were OK: https://github.com/apache/nuttx/tree/656883fec5561ca91502a26bf018473ca0229aa4

NuttX Commit #3: Belated Commits fail at test_ltp_interfaces_pthread_barrierattr_init_2_1: https://github.com/apache/nuttx/issues/14808#issuecomment-2518119367

## Apps Commits

Earlier NuttX Apps Commits were OK: https://github.com/apache/nuttx-apps/tree/1c7a7f7529475b0d535e2088a9c4e1532c487156

Later NuttX Apps Commits were ???: https://github.com/apache/nuttx-apps/tree/3c4ddd2802a189fccc802230ab946d50a97cb93c

Belated NuttX Apps Commits were ???

```bash
## TODO: Install Docker Engine
## https://docs.docker.com/engine/install/ubuntu/

## TODO: For WSL, we may need to install Docker on Native Windows
## https://github.com/apache/nuttx/issues/14601#issuecomment-2453595402

## TODO: Bisect CI Job
job=risc-v-05

## NuttX Commit #1 (14 Nov 2024): Runs OK
## nuttx_hash=6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c

## NuttX Commit #2: Runs OK
## nuttx_hash=656883fec5561ca91502a26bf018473ca0229aa4

## NuttX Commit #3 (4 Dec 2024): Fails at test_ltp_interfaces_pthread_barrierattr_init_2_1
## https://github.com/apache/nuttx/issues/14808#issuecomment-2518119367
## test_open_posix/test_openposix_.py::test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED   [ 17%]
nuttx_hash=79a1ebb9cd0c13f48a57413fa4bc3950b2cd5e0b

## Apps Commit #1: Runs OK
apps_hash=1c7a7f7529475b0d535e2088a9c4e1532c487156

## Apps Commit #2: ???
## apps_hash=1c7a7f7529475b0d535e2088a9c4e1532c487156

## Apps Commit #3: ???
## https://github.com/apache/nuttx/issues/14808#issuecomment-2518119367
## apps_hash=ce217b874437b2bd60ad2a2343442506cd8b50b8

sudo ./run-job-bisect.sh $job $nuttx_hash $apps_hash
```

[NuttX Commit #1: Runs OK. nuttx_hash=6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c](https://gist.github.com/lupyuen/89759c53accbf6caa717b39fd5e69bae)

[NuttX Commit #2: Runs OK. nuttx_hash=656883fec5561ca91502a26bf018473ca0229aa4](https://gist.github.com/lupyuen/e22cd208bd9ed3e36e59de2b44bb85ef)

[NuttX Commit #3: Fails at test_ltp_interfaces_pthread_barrierattr_init_2_1. nuttx_hash=79a1ebb9cd0c13f48a57413fa4bc3950b2cd5e0b](https://gist.github.com/lupyuen/27cb7f5359bc0a8176db9815ba8b162a)

Assume will terminate in 1 hour! Actually terminates in 30 mins. Change this for your machine!

Press Ctrl-C very carefully, don't crash Docker!

How many commits between 14 Nov and 4 Dec?

Now that we can bisect reliably and automatically: Shall we do this for All Failed Builds?

NuttX Hash vs Apps Hash

But NuttX Commit might not compile with Apps Commit, must be compatible

Maybe return special exit code 125 if can't compile

Inconsistent CI Test?

[run-job-bisect.sh risc-v-05 94a2ce3641213cc702abc5c17b0f81a50c714a2e 1c7a7f7529475b0d535e2088a9c4e1532c487156 / fails at test_ltp_interfaces_sigaction_12_35](https://gist.github.com/lupyuen/7c9fa7d30fed3fe73ffeb7e7f1ddd0fb)

Let it simmer overnight (probably 7 hours, like my Bean Stew)

Locoroco merging into big bubbles

Did git bisect find the breaking commit? 

Erm not quite.

Always run twice 

That's 2 bean stews!

_So it's like travelling back in time, changing something in history, and the future changes?

Um.somegthing like thst

# TODO

Current Failure: [rv-virt:citest fails with Load Access Fault at ltp_interfaces_pthread_barrierattr_init_2_1 (risc-v-05)](https://github.com/apache/nuttx/issues/15170)

Previous Failure: [rv-virt/citest: test_hello or test_pipe failed](https://github.com/apache/nuttx/issues/14808)

Due to: [arch/toolchain: Add toolchain gcc](https://github.com/apache/nuttx/pull/14779)

Fixed by: [rv-virt/citest: Increase init task stack size to 3072](https://github.com/apache/nuttx/pull/15165)

TODO: Test Git Bisect

```bash
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
cd nuttx

git bisect start
git bisect bad HEAD
git bisect good 656883fec5561ca91502a26bf018473ca0229aa4
git bisect run my_test_script.sh

https://git-scm.com/docs/git-bisect
$ git bisect visualize
$ git bisect visualize --stat
$ git bisect log
```

https://github.com/lupyuen/nuttx-bisect/blob/main/run.sh

https://github.com/lupyuen/nuttx-bisect/blob/main/my-test-script.sh

[git bisect run my-test-script.sh](https://gist.github.com/lupyuen/e822323378e09ae3c24a41c5f42abfd0)

TODO: With Docker

```bash
sudo docker run \
  -it \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash
cd
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/$(git rev-parse HEAD) ; popd
pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/$(git rev-parse HEAD) ; popd
cd nuttx/tools/ci
./cibuild.sh -c -A -N -R testlist/risc-v-05.dat 
[ Wait for it to fail. Then press Ctrl-C a few times to stop it ]
cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*
```

# Check Size

```text
## https://github.com/google/bloaty
$ /tools/bloaty/bin/bloaty /root/nuttx/nuttx 
    FILE SIZE        VM SIZE    
 --------------  -------------- 
  46.1%  6.80Mi   0.0%       0    .debug_info
  17.1%  2.53Mi   0.0%       0    .debug_line
   8.6%  1.26Mi   0.0%       0    .debug_abbrev
   6.6%  1000Ki   0.0%       0    .debug_loclists
   6.2%   941Ki  64.9%   941Ki    .text
   5.1%   772Ki   0.0%       0    .debug_str
   2.5%   381Ki  26.3%   381Ki    .rodata
   1.8%   277Ki   0.0%       0    .debug_frame
   1.7%   254Ki   0.0%       0    .symtab
   1.2%   174Ki   0.0%       0    .strtab
   1.1%   166Ki   0.0%       0    .debug_rnglists
   1.1%   164Ki   0.0%       0    .debug_line_str
   0.0%       0   8.1%   118Ki    .bss
   0.8%   114Ki   0.0%       0    .debug_aranges
   0.1%  8.31Ki   0.6%  8.27Ki    .data
   0.0%  5.00Ki   0.1%     858    [104 Others]
   0.0%  3.89Ki   0.0%       0    [Unmapped]
   0.0%  2.97Ki   0.0%       0    .shstrtab
   0.0%     296   0.0%     256    .srodata.cst8
   0.0%     196   0.0%       0    [ELF Headers]
   0.0%     144   0.0%     104    .sdata.called
 100.0%  14.8Mi 100.0%  1.42Mi    TOTAL

$ /tools/bloaty/bin/bloaty /root/nuttx/nuttx -d compileunits
bloaty: Unknown ELF machine value: 243'

Fuchsia supports it:
https://fuchsia.googlesource.com/third_party/bloaty/+/53360fd9826a417671a92386306745bfd5755f21%5E1..53360fd9826a417671a92386306745bfd5755f21/

cd
git clone https://fuchsia.googlesource.com/third_party/bloaty
cd bloaty
cmake -B build -G Ninja -S .
cmake --build build
cd /root/nuttx
/root/bloaty/build/bloaty nuttx -d compileunits,segments,sections,symbols

https://github.com/lupyuen/nuttx-bisect/releases/download/main-1/bloaty.log
```

# Dump the disassembly

```text
## Dump the disassembly to nuttx.S
cd /root/nuttx
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1
sudo docker cp nuttx:/root/nuttx/nuttx.S .

https://github.com/lupyuen/nuttx-bisect/releases/download/main-1/nuttx.S
```

TODO: Search disassembly for ltp_interfaces_pthread_barrierattr_init_2_1

```text
8006642c <ltp_interfaces_pthread_barrierattr_init_2_1_main>:
ltp_interfaces_pthread_barrierattr_init_2_1_main():
/root/apps/testing/ltp/ltp/testcases/open_posix_testsuite/conformance/interfaces/pthread_barrierattr_init/2-1.c:27
#include "posixtest.h"

#define BARRIER_NUM 100

int main(void)
{
8006642c:	7149                	add	sp,sp,-368
8006642e:	72fd                	lui	t0,0xfffff
/root/apps/testing/ltp/ltp/testcases/open_posix_testsuite/conformance/interfaces/pthread_barrierattr_init/2-1.c:34
	pthread_barrierattr_t ba;
	pthread_barrier_t barriers[BARRIER_NUM];
	int cnt;
```

Which points to https://github.com/apache/nuttx-apps/tree/master/testing/ltp

```text
sudo docker cp nuttx:/root/apps/testing/ltp/Kconfig /tmp
nano /tmp/Kconfig
sudo docker cp /tmp/Kconfig nuttx:/root/apps/testing/ltp/Kconfig
```

Change:
```text
config TESTING_LTP_STACKSIZE
	int "Linux Test Project stack size"
	default 4096
```
To:
```text
config TESTING_LTP_STACKSIZE
	int "Linux Test Project stack size"
	default 8192
```
And copy to docker.

Re-run:

```text
cd /root/nuttx
make distclean
cd tools/ci
./cibuild.sh -c -A -N -R testlist/risc-v-05.dat 
[ Wait for it to fail. Then press Ctrl-C a few times to stop it ]
cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*
```

Or:

```text
sudo docker exec \
  -it \
  nuttx \
  /bin/bash
cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*
```

Fixed yay! [testing/ltp: Increase Stack Size](https://github.com/apache/nuttx-apps/pull/2888)

# Bisect Run

https://git-scm.com/docs/git-bisect#_bisect_run

If you have a script that can tell if the current source code is good or bad, you can bisect by issuing the command:

$ git bisect run my_script arguments

Note that the script (my_script in the above example) should exit with code 0 if the current source code is good/old, and exit with a code between 1 and 127 (inclusive), except 125, if the current source code is bad/new.

Any other exit code will abort the bisect process. It should be noted that a program that terminates via exit(-1) leaves $? = 255, (see the exit(3) manual page), as the value is chopped with & 0377.

The special exit code 125 should be used when the current source code cannot be tested. If the script exits with this code, the current revision will be skipped (see git bisect skip above). 125 was chosen as the highest sensible value to use for this purpose, because 126 and 127 are used by POSIX shells to signal specific error status (127 is for command not found, 126 is for command found but not executable—​these details do not matter, as they are normal errors in the script, as far as bisect run is concerned).

You may often find that during a bisect session you want to have temporary modifications (e.g. s/#define DEBUG 0/#define DEBUG 1/ in a header file, or "revision that does not have this commit needs this patch applied to work around another problem this bisection is not interested in") applied to the revision being tested.

To cope with such a situation, after the inner git bisect finds the next revision to test, the script can apply the patch before compiling, run the real test, and afterwards decide if the revision (possibly with the needed patch) passed the test and then rewind the tree to the pristine state. Finally the script should exit with the status of the real test to let the git bisect run command loop determine the eventual outcome of the bisect session.

# What's Next

TODO

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen), for sticking with me all these years.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/bisect.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/bisect.md)
