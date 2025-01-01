# Git Bisecting a Bug (Apache NuttX RTOS)

📝 _31 Jan 2024_

![Git Bisecting a Bug in Apache NuttX RTOS](https://lupyuen.github.io/images/bisect-title.jpg)

<span style="font-size:80%">

> _"Because I'm bad, I'm bad, shamone <br> (bad, bad, really, really bad) <br>
You know I'm bad, I'm bad (bad, bad) ... <br>
And the whole world has to answer right now <br>
Just to tell you once again <br>
[Who's bad?](https://en.wikipedia.org/wiki/Bad_(Michael_Jackson_song))"_

</span>

2 Weeks Ago: We spoke of a [__Runtime Bug__](https://lupyuen.github.io/articles/ci7) in __Apache NuttX RTOS__. We think that the __Breaking Commit__ falls somewhere between these [__"Good" and "Bad" Commits__](https://docs.google.com/spreadsheets/d/1aNu1OensFc-QA1EfyTe6CcbfduzR3gdbbnZfRTca0fw/edit?gid=0#gid=0)...

| | |
|:-----------:|:--------:|
| [__Commit #1 is Good__](https://github.com/apache/nuttx/issues/14808#issue-2661180633) <br> _2024-11-14_ | NuttX runs OK <br> [_6554ed4_](https://github.com/apache/nuttx/tree/6554ed4d668e0c3982aaed8d8fb4b8ae81e5596c)
| _[ many many commits ]_ | _..._
| [__Commit #468 is Bad__](https://github.com/apache/nuttx/issues/14808#issuecomment-2518119367) <br> _2024-12-04_ | NuttX won't run <br> [_79a1ebb_](https://github.com/apache/nuttx/tree/79a1ebb9cd0c13f48a57413fa4bc3950b2cd5e0b)

That's [__468 Commits__](https://docs.google.com/spreadsheets/d/1aNu1OensFc-QA1EfyTe6CcbfduzR3gdbbnZfRTca0fw/edit?gid=0#gid=0). Which one is the Breaking Commit?

_Maybe we Rewind Each Commit and test?_

With a script, we could rewind and retest 468 Commits for [__Compile Errors__](https://lupyuen.github.io/articles/ci6). But it's probably too slow for __Runtime Errors__. _(Rewind + recompile + rerun)_

We have a quicker way: __Git Bisect__!

# Automated Bisect

_What's this Git Bisect?_

Remember [__Binary Chop__](https://en.wikipedia.org/wiki/Binary_search)?

> _"I'm thining of A Number <br> Guess My Number! <br> It's from 1 to 468 <br> Ask me 9 Yes-No Questions"_

To solve this, we __Divide And Conquer__: Is 234 too high? _(no)_ Is 351 too high? _(yes)_ Is 292 too high _(yes)_...

TODO: Pic of Divide-And-Conquer

[__Git Bisect__](https://git-scm.com/docs/git-bisect) works the same way, but for __Git Commits__...

- Our __Breaking Commit__ is one of 468 Commits

- Git Bisect shall __Pick the Middle Commit__ and ask: "Is this a Good Commit or Bad Commit?"

- Repeat until it discovers the __Breaking Commit__ (in 9 steps)

_Is it automated?_

Yep Git Bisect will gleefully seek the Breaking Commit on its own... Assuming that we provide a Script to __Assess the Goodness / Badness__ of a NuttX Commit: [my-test-script.sh](https://github.com/lupyuen/nuttx-bisect/blob/main/my-test-script.sh)

```bash
## This script will be called by Git Bisect...
## In Case of Error: Return the error to Git Bisect
set -e

## Get the NuttX Hash (Commit ID)
nuttx_hash=$(git rev-parse HEAD)

## For the NuttX Commit:
## We Build, Run and Test the NuttX Commit...
## make distclean || true
## tools/configure.sh ox64:nsh
## make -j

## But for now: We randomly simulate OK or Error
random_0_or_1=$(( $RANDOM % 2 ))
if (( "$random_0_or_1" == "0" )); then
  exit 0  ## Simulate OK
else
  exit 1  ## Simulate Error
fi
```

[(Or something __more predictable__)](https://github.com/lupyuen/nuttx-bisect/blob/main/my-test-script.sh#L34-L76)

[(Or do it __manually__)](https://git-scm.com/docs/git-bisect#_basic_bisect_commands_start_bad_good)

This is how we start our __Simulated Git Bisect__: [run.sh](https://github.com/lupyuen/nuttx-bisect/blob/main/run.sh)

```bash
## Download the NuttX Repo
git clone https://github.com/apache/nuttx
cd nuttx

## Tell Git Bisect the Good and Bad Commits
## (Or specify HEAD for the Latest Commit)
git bisect start
git bisect good 6554ed4  ## Commit #1 is Good
git bisect bad  79a1ebb  ## Commit #468 is Bad

## Bisect with our Simulated Test Script
git bisect run \
  $HOME/nuttx-bisect/my-test-script.sh
...
## Commit #235 is the Breaking Commit:
## 74bac565397dea37ebfc3ac0b7b7532737738279 is the first bad commit
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/160613f2b68f1ab81f1c46146c189b9f)

That was quick! We break it down...

![Simulating The Git Bisect](https://lupyuen.github.io/images/bisect-screen1.png)

# Simulate The Git Bisect

_What just happened in Git Bisect?_

1.  Git Bisect picked the [__Middle Commit #`234`__](https://gist.github.com/lupyuen/160613f2b68f1ab81f1c46146c189b9f#file-gistfile1-txt-L38-L69)...

    ```bash
    ## Testing Commit #234 (94a2ce3)
    $HOME/nuttx-bisect/my-test-script.sh
    nuttx_hash=94a2ce3

    ## Our Script simulates a successful test
    Simulate OK
    exit 0
    ```
    
    And discovered that __Commit #`234` is Good__. (Via our Simulated Script)

1.  Then it continued the simulated bisecting...

    ```bash
    ## Commit #351 is Bad
    nuttx_hash=1cfaff0
    Simulate Error
    exit 1

    ## Commit #292 is Bad
    nuttx_hash=65a93e9
    Simulate Error
    exit 1

    ## Commit #263 is Bad
    nuttx_hash=1e265af
    Simulate Error
    exit 1

    ## Commit #248 is Bad
    nuttx_hash=c70f3e3
    Simulate Error
    exit 1

    ## Commit #241 is Bad
    nuttx_hash=5d86bee
    Simulate Error
    exit 1

    ## Commit #237 is Bad
    nuttx_hash=e7c2e7c
    Simulate Error
    exit 1

    ## Commit #236 is Bad
    nuttx_hash=68d47ee
    Simulate Error
    exit 1

    ## Commit #235 is Bad
    nuttx_hash=74bac56
    Simulate Error
    exit 1
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/160613f2b68f1ab81f1c46146c189b9f)

1.  Finally deducing that __Commit #`235`__ is the __Breaking Commit__

    ```bash
    ## Commit #235 is the Breaking Commit
    74bac56 is the first bad commit
    ```

This works fine for our (randomised) __Simulated Git Bisect__. Now we do it for real...

![Docker running CI Test in CI Job risc-v-05](https://lupyuen.github.io/images/bisect-screen2.png)

# Continuous Integration Test

_Will Git Bisect work for Real-Life NuttX?_

From our [__Bug Report__](https://github.com/apache/nuttx/issues/14808): NuttX fails the __Continuous Integration Test__ (CI Test) for RISC-V QEMU.

```text
Configuration/Tool: rv-virt/citest
test_cmocka      PASSED
test_hello       PASSED
test_helloxx     FAILED
test_pipe        FAILED
test_usrsocktest FAILED
[...Failing all the way...]
```

This happens inside the __CI Job _risc-v-05___. Which we can reproduce with __Docker Engine__: [run-job-bisect.sh](https://github.com/lupyuen/nuttx-bisect/blob/main/run-job-bisect.sh#L36-L61)

```bash
## Assume we're running risc-v-05 with
## Latest NuttX Repo and NuttX Apps
job=risc-v-05
nuttx_hash=HEAD
apps_hash=HEAD

## Run the CI Job in Docker Container
## If CI Test Hangs: Kill it after 1 hour
sudo docker run -it \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash -c "
  set -e ;
  set -x ;
  uname -a ;
  cd ;
  pwd ;
  git clone https://github.com/apache/nuttx ;
  git clone https://github.com/apache/nuttx-apps apps ;
  echo Building nuttx @ $nuttx_hash / nuttx-apps @ $apps_hash ;
  pushd nuttx ; git reset --hard $nuttx_hash ; popd ;
  pushd apps  ; git reset --hard $apps_hash  ; popd ;
  pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/\$(git rev-parse HEAD)    ; popd ;
  pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/\$(git rev-parse HEAD) ; popd ;
  sleep 10 ;
  cd nuttx/tools/ci ;
  ( sleep 3600 ; echo Killing pytest after timeout... ; pkill -f pytest )&
  (
    (./cibuild.sh -c -A -N -R testlist/$job.dat) || (res=\$? ; echo '***** JOB FAILED' ; exit \$res)
  )
"
```

Everything above becomes our __Git Bisect Script__ that assesses "Goodness" vs "Badness" for a NuttX Commit: [run-job-bisect.sh](https://github.com/lupyuen/nuttx-bisect/blob/main/run-job-bisect.sh#L36-L73)

```bash
## This script will be called by Git Bisect Wrapper...
## We run the CI Job in Docker Container
## (Copy from above)
sudo docker run -it ...

## Result the result to the caller
res=$?
if [[ "$res" == "0" ]] ; then
  exit 0  ## Return OK
else
  exit 1  ## Return Error
fi
```

Which is called by our __Git Bisect Wrapper__: [start-job-bisect.sh](https://github.com/lupyuen/nuttx-bisect/blob/main/start-job-bisect.sh)

```bash
## This wrapper script will be called by Git Bisect
## Must be run as `sudo`! (Because of Docker)
## Get the NuttX Hash (Commit ID)
nuttx_hash=$(git rev-parse HEAD)

## Run the CI Job for the NuttX Commit
## Passing the Job Name, NuttX Hash and Apps Hash
## (Or set Apps Hash to HEAD for the Latest Commit)
job=risc-v-05
apps_hash=1c7a7f7529475b0d535e2088a9c4e1532c487156
$HOME/nuttx-bisect/run-job-bisect.sh \
  $job $nuttx_hash $apps_hash

## This Git Bisect script will work for any CI Job!
## Just change `job=risc-v-05` to the CI Job Name (like arm-01)
```

We're ready to run this!

![Running Git Bisect on Real NuttX Commits](https://lupyuen.github.io/images/bisect-screen3.png)

# Git Bisect For Real

_What happens in Git Bisect?_

1.  We start Git Bisect, telling it that Commit #`1` is Good and Commit #`468` is Bad: [run2.sh](https://github.com/lupyuen/nuttx-bisect/blob/main/run2.sh)

    ```bash
    sudo --shell  ## Needed by Docker
    git clone https://github.com/apache/nuttx
    cd nuttx
    git bisect start
    git bisect good 6554ed4d  ## Commit #1
    git bisect bad  79a1ebb   ## Commit #468
    git bisect run \
      $HOME/nuttx-bisect/start-job-bisect.sh
    ```

1.  Git Bisect picks the [__Middle Commit #`234`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L42-L74) and runs our script

    ```bash
    ## Testing Commit #234 (94a2ce3)
    ## For CI Job risc-v-05 (CI Test for RISC-V QEMU)
    ## With NuttX Apps (1c7a7f7)
    $HOME/nuttx-bisect/run-job-bisect.sh \
      risc-v-05 \
      94a2ce3 \
      1c7a7f7
    ```

1.  And discovers that [__Commit #`234` is Good__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1260-L1379) (via our script)

    ```bash
    ## Commit #234: Completed CI Test successfully
    Configuration/Tool: rv-virt/citest
    test_ostest PASSED
    exit 0
    ```

1.  Then it continues bisecting. Assessing Commits [#`351`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1386-L1420), [#`292`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1876-L1912), [#`263`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L2367-L2405), [#`248`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3028-L3068), [#`241`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3524-L3566), [#`237`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3935-L3979), [#`236`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4325-L4371), [#`235`](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4683-L4731)

    ```bash
    ## Commit #351 is Bad
    run-job-bisect.sh ... 1cfaff0 ...test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
    exit 1

    ## Commit #292 is Bad
    run-job-bisect.sh ... 65a93e9 ...
    test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED 
    exit 1

    ## Commit #263 is Bad
    run-job-bisect.sh ... 1e265af ...
    test_ltp_interfaces_sigrelse_1_1 FAILED
    exit 1

    ## Commit #248 is Bad
    run-job-bisect.sh ... c70f3e3 ...
    test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
    exit 1

    ## Commit #241 is Bad
    run-job-bisect.sh ... 5d86bee ...
    test_ltp_interfaces_mq_open_7_3 FAILED
    exit 1

    ## Commit #237 is Bad
    run-job-bisect.sh ... e7c2e7c ...
    test_ltp_interfaces_sigaction_23_7 FAILED
    exit 1

    ## Commit #236 is Bad
    run-job-bisect.sh ... 68d47ee ...
    test_ltp_interfaces_pthread_getcpuclockid_1_1 FAILED
    exit 1

    ## Commit #235 is Bad
    run-job-bisect.sh ... 74bac56 ...
    test_ltp_interfaces_pthread_detach_1_1 FAILED
    exit 1
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d)

1.  Which says in 9 steps (pic below)

    |||
    |:---:|:---:|
    | _Commit #468_ | _Is Bad_
    | [__Commit #`234`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L42-L74) | [__Is Good__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1260-L1379)
    | [__Commit #`351`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1386-L1420) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1789-L1869)
    | [__Commit #`292`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L1876-L1912) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L2281-L2360)
    | [__Commit #`263`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L2367-L2405) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L2949-L3021)
    | [__Commit #`248`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3028-L3068) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3437-L3517)
    | [__Commit #`241`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3524-L3566) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3845-L3928)
    | [__Commit #`237`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L3935-L3979) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4235-L4318)
    | [__Commit #`236`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4325-L4371) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4591-L4676)
    | [__Commit #`235`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4683-L4731) | [_Is Bad_](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L5087-L5166) <br> _(really really)_

1.  Finally deducing that [__Commit #`235`__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L4683-L4731) is the [__Breaking Commit__](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d#file-gistfile1-txt-L5167-L5210) (pic below)

    ```bash
    ## Commit #235 is the Breaking Commit
    74bac56 is the first bad commit
    ```

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/39cdb916d30625388974e00d5daa676d)

![Git Bisecting a Bug in Apache NuttX RTOS](https://lupyuen.github.io/images/bisect-title.jpg)

# Git Bisect Gets Quirky

_Did Git Bisect find the correct Breaking Commit?_

To be absolutely sure: We run Git Bisect [__one more time__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493)...

```bash
## Commit #234 is Bad
run-job-bisect.sh ... 94a2ce3 ...
test_ltp_interfaces_mq_close_3_2 FAILED
exit 1

## Commit #117 is Good
run-job-bisect.sh ... 96a3bc2 ...
test_ostest PASSED
exit 0

## Commit #138 is Bad
run-job-bisect.sh ... 3a46b6e ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #146 is Bad
run-job-bisect.sh ... dac3f31 ...
test_ltp_interfaces_sigaction_6_3 FAILED
exit 1

## Commit #131 is Good
run-job-bisect.sh ... 4c3ae2e ...
test_ostest PASSED
exit 0

## Commit #138 is Bad
run-job-bisect.sh ... 3b50bf1 ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #134 is Bad
run-job-bisect.sh ... 5ff98f6 ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #133 is Bad
run-job-bisect.sh ... b4d8ac8 ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #132 is Bad
run-job-bisect.sh ... fb92b60 ...
test_ltp_interfaces_pthread_barrierattr_init_2_1 FAILED
exit 1

## Commit #132 is the Breaking Commit
fb92b60 is the first bad commit

## Previously: Commit #235 is the Breaking Commit!
## 74bac56 is the first bad commit
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493)

__Commit #`132`__ is now the Breaking Commit, not Commit #`235`!

Hmmm something below has changed. Why?

|||
|:---:|:---:|
| _Commit #468_ | _Is Bad_
| [__Commit #`234`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L46-L78) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L337-L421)
| [__Commit #`117`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L428-L462) | [__Is Good__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L1648-L1767)
| [__Commit #`138`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L1774-L1810) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L2179-L2259)
| [__Commit #`146`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L2266-L2304) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L2646-L2726)
| [__Commit #`131`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L2733-L2773) | [__Is Good__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L3959-L4078)
| [__Commit #`138`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L4085-L4127) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L4496-L4575)
| [__Commit #`134`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L4582-L4626) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L4995-L5074)
| [__Commit #`133`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L5081-L5127) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L5496-L5575)
| [__Commit #`132`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L5582-L5630) | [_Is Bad_](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L5999-L6078)
| [__Commit #`132`__](https://gist.github.com/lupyuen/5a92fb9ea76751a54d2a82ba0341c493#file-gistfile1-txt-L6079-L6123) | Is the __Breaking Commit__ <br> _(really really?)_

# Good Commit Goes Bad

_Why is Git Bisect telling us a different Breaking Commit?_

In The Movies: Arnold travels to the past _(in a Time Machine)_, changing something in history, and the future changes.

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

After this, everything changed. Concluding with a __Different Breaking Commit__. (Think "alternate timeline")

_Huh! How did Commit #234 change?_

This CI Test looks more complicated than we thought. CI Test appears to be __failing with the slightest change__ in QEMU Memory. For a Specific Commit: Our bug isn't reliably reproducible.

__Lesson Learnt:__ Git Bisect works best for bugs that are __reliably reproducible__ for a specified commit!

_Can we use Git Bisect with Real Hardware? On an Actual NuttX Device?_

Yep sure Git Bisect will work with any NuttX Device that be __controlled by a script__! For Example: __SG2000 RISC-V SBC__ has a script for Building NuttX and Booting via TFTP (which can talk to Git Bisect)

- [__"Daily Automated Testing for Milk-V Duo S RISC-V SBC"__](https://lupyuen.github.io/articles/sg2000a)

Though Honestly: __SG2000 Emulator__ would be much quicker (and more reliable) for Git Bisect...

- [__RISC-V Emulator for Sophgo SG2000 SoC (Pine64 Oz64 / Milk-V Duo S)__](https://lupyuen.github.io/articles/sg2000b)

![We have Two Bugs stacked together](https://lupyuen.github.io/images/bisect-issues.jpg)

# Fixing The Bug

_OK so Git Bisect wasn't 100% successful. How did we fix the bug?_

Actually we have __Two Bugs__ stacked together...

- [__"rv-virt/citest: test_hello or test_pipe failed"__](https://github.com/apache/nuttx/issues/14808)

- [__"rv-virt:citest fails with Load Access Fault at ltp_interfaces_pthread_barrierattr_init_2_1 (risc-v-05)"__](https://github.com/apache/nuttx/issues/15170)

The First Bug was a Stack Overflow that __Tiago Medicci Serrano__ kindly fixed by increasing the __Init Task Stack Size__...

- [__"rv-virt/citest: Increase init task stack size to 3072"__](https://github.com/apache/nuttx/pull/15165)

The Second Bug? Not so obvious which Stack Overflowed...

```bash
## Start the NuttX Docker Image
sudo docker run \
  -it \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash

## Run the CI Test in Docker
cd
git clone https://github.com/apache/nuttx
git clone https://github.com/apache/nuttx-apps apps
pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/$(git rev-parse HEAD) ; popd
pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/$(git rev-parse HEAD) ; popd
cd nuttx/tools/ci
./cibuild.sh -c -A -N -R testlist/risc-v-05.dat 

## Wait for it to fail
## Press Ctrl-C a few times to stop it
## Then dump the log
cat /root/nuttx/boards/risc-v/qemu-rv/rv-virt/configs/citest/logs/rv-virt/qemu/*

## Output shows: Stack Overflow for ltp_interfaces_pthread_barrierattr_init_2_1
nsh> ltp_interfaces_pthread_barrierattr_init_2_1
riscv_exception: EXCEPTION: Load access fault. MCAUSE: 00000005, EPC: 800074c6, MTVAL: 000002a4
STACKSIZE  USED  FILLED   COMMAND
 3936      3936  100.0%!  ltp_interfaces_pthread_barriera
```

Needs more probing...

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4ec372cea171b99ae5bc5603aa75a6a7)

![Searching the NuttX Disassembly for ltp_interfaces_pthread_barrierattr_init_2_1](https://lupyuen.github.io/images/bisect-disassembly.png)

# Increase The Stack

_What's ltp_interfaces_pthread_barrierattr_init_2_1? Why is the Stack Overflowing?_

We search the __NuttX Disassembly__...

```bash
## Dump the disassembly to nuttx.S
cd /root/nuttx
riscv-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1

## Search the disassembly for ltp_interfaces_pthread_barrierattr_init_2_1
grep nuttx.S \
  ltp_interfaces_pthread_barrierattr_init_2_1
```

[(See the __NuttX Disassembly__)](https://github.com/lupyuen/nuttx-bisect/releases/download/main-1/nuttx.S)

And we see...

```text
8006642c <ltp_interfaces_pthread_barrierattr_init_2_1_main>:
  ltp_interfaces_pthread_barrierattr_init_2_1_main():
    apps/testing/ltp/ltp/testcases/open_posix_testsuite/conformance/interfaces/pthread_barrierattr_init
```

Aha! It points to a __NuttX Test App__: [nuttx-apps/testing/ltp](https://github.com/apache/nuttx-apps/tree/master/testing/ltp)

Thus we edit the __Stack Configuration__: [testing/ltp/Kconfig](https://github.com/apache/nuttx-apps/tree/master/testing/ltp/Kconfig)

```yaml
## Before: Stack Size is 4 KB
config TESTING_LTP_STACKSIZE
  int "Linux Test Project stack size"
  default 4096
```

We double the __Stack Size to 8 KB__...

```yml
  ## After: Stack Size is 8 KB
  default 8192
```

We retest in Docker. And our [__CI Test succeeds__](https://gist.github.com/lupyuen/3688826ed676971536249509ceefe834) yay!

- [__"testing/ltp: Increase Stack Size"__](https://github.com/apache/nuttx-apps/pull/2888)

_But why did we run out of Stack Space? Has something grown too big?_

We could run __Bloaty__ to do detailed analysis of the __Code and Data Size__...

- [__"Inspect Executable Size with Bloaty"__](https://lupyuen.github.io/articles/bisect#appendix-inspect-executable-size-with-bloaty)

![Git Bisecting a Bug in Apache NuttX RTOS](https://lupyuen.github.io/images/bisect-title.jpg)

# What's Next

TODO: Why Git Bisect? Because each test runs for 1 hour!

TODO: Let it simmer overnight (probably 7 hours, like my Bean Stew)

TODO: Locoroco merging into big bubbles

Next Article: What would NuttX Life be like without GitHub? We try out (self-hosted open-source) __Forgejo Git Forge__ with NuttX.

After That: Why __Sync-Build-Ingest__ is super important for NuttX CI. And how we monitor it with our __Magic Disco Light__.

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And [__My Sponsors__](https://lupyuen.github.io/articles/sponsor), for sticking with me all these years.

- [__Sponsor me a coffee__](https://lupyuen.github.io/articles/sponsor)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.github.io)

- [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/bisect.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/bisect.md)

# Appendix: Inspect Executable Size with Bloaty

_Earlier we ran out of Stack Space. Has something grown too big?_

We could run __Bloaty__ to do detailed analysis of the __Code and Data Size__...

- [__github.com/google/bloaty__](https://github.com/google/bloaty)

For quick experimentation: Bloaty is bundled inside our __NuttX Docker Image__...

```bash
## Inside NuttX Docker:
## Assume we compiled NuttX at /root/nuttx/nuttx
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

## Let's dump the details
## For NuttX QEMU RISC-V
$ /tools/bloaty/bin/bloaty \
  /root/nuttx/nuttx \
  -d compileunits
bloaty: Unknown ELF machine value: 243

## Oops Bloaty won't work for RISC-V Executable!
```

Standard Bloaty won't support RISC-V. But [__Fuchsia Bloaty__](https://fuchsia.googlesource.com/third_party/bloaty/+/53360fd9826a417671a92386306745bfd5755f21%5E1..53360fd9826a417671a92386306745bfd5755f21/) supports it.

We compile and run __Fuchsia Bloaty__...

```bash
## Compile Fuchsia Bloaty for RISC-V Support
git clone https://fuchsia.googlesource.com/third_party/bloaty
cd bloaty
cmake -B build -G Ninja -S .
cmake --build build

## Run Fuchsia Bloaty on NuttX QEMU RISC-V
## Dump all the details
cd /root/nuttx
/root/bloaty/build/bloaty nuttx \
  -d compileunits,segments,sections,symbols
```

Now we see everything in our NuttX RISC-V Executable...

```text
    FILE SIZE        VM SIZE    
 --------------  -------------- 
  62.7%  9.26Mi  66.2%   960Ki    [2505 Others]
   7.5%  1.11Mi   4.8%  69.2Ki    EEE6secondB8un170006Ev
    94.1%  1.04Mi   0.0%       0    [Unmapped]
      55.6%   594Ki   NAN%       0    .debug_info
      21.3%   227Ki   NAN%       0    .debug_line
      17.4%   185Ki   NAN%       0    .debug_str
       3.1%  33.7Ki   NAN%       0    .strtab
        54.6%  18.4Ki   NAN%       0    [160 Others]
         7.8%  2.61Ki   NAN%       0    std::__1::(anonymous namespace)::make<>()::buf
         6.5%  2.20Ki   NAN%       0    std::__1::num_get<>::do_get()
         4.5%  1.52Ki   NAN%       0    std::__1::num_put<>::do_put()
```

[(See the __Complete Log__)](https://github.com/lupyuen/nuttx-bisect/releases/download/main-1/bloaty.log)
