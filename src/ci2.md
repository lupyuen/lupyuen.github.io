# Your very own Build Farm for Apache NuttX RTOS

📝 _20 Nov 2024_

![TODO](https://lupyuen.github.io/images/ci2-title.jpg)

[__Refurbished Ubuntu PCs__](TODO) have become quite affordable ($??? pic above). Can we turn them into a __(Low-Cost) Build Farm__ for [__Apache NuttX RTOS__](TODO)?

_Why not do all this in GitHub Actions? It's free ain't it?_

We learnt a Painful Lesson: __Freebies Won't Last Forever!__ It's probably a bad idea to be locked-in and over-dependent on a __Single Provider for Continuous Integration__. That's why we're exploring alternatives...

- TODO: Reducing GitHub Runners

TODO

# Inside a Target Group

TODO: `arm-01` has all the cool classic boards...

`arm-06` has RP2040 Boards...

`risc-v-01` has ???

TODO: Filesystem wildcards

```text
## This Target Group includes ???

## Exclude mosh

## CMake
```

# Build NuttX for a Target Group

TODO: CI Jobs `arm-01` to `arm-14`

[NuttX Builds for CI](https://docs.google.com/spreadsheets/d/1OdBxe30Sw3yhH0PyZtgmefelOL56fA6p26vMgHV0MRY/edit?gid=0#gid=0)

TODO: Docker Image for NuttX

TODO: Install Docker

Suppose we wish to compile the Targets for `arm-01`...

TODO: Pic of targets

Here are the steps...

1.  Install Docker

1.  Download the Docker Image for NuttX

1.  Check out the `master` branch of `nuttx` repo

1.  Do the same for `nuttx-apps` repo

1.  Build the Targets for `arm-01`

    (With the NuttX Docker Image)

1.  Wait for `arm-01` to complete

    (About 1.5 hours)

This is how we do it: [run-job.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-job.sh)

```bash
## Run a NuttX CI Job with Docker
## Parameter is thr CI Job, like "arm-01"
job=$1

## TODO: Install Docker

## Download the Docker Image for NuttX
sudo docker pull \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest

## Run the CI Job in the Docker Container
sudo docker run -it \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash -c "
  cd ;
  pwd ;
  git clone https://github.com/apache/nuttx ;
  git clone https://github.com/apache/nuttx-apps apps ;
  pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/\$(git rev-parse HEAD) ; popd ;
  pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/\$(git rev-parse HEAD) ; popd ;
  cd nuttx/tools/ci ;
  ./cibuild.sh -c -A -N -R testlist/$job.dat ;
"
```

We run it like this...

```bash
$ sudo ./run-job.sh arm-01
NuttX Source: https://github.com/apache/nuttx/tree/9c1e0d3d640a297cab9f2bfeedff02f6ce7a8162
NuttX Apps: https://github.com/apache/nuttx-apps/tree/52a50ea72a2d88ff5b7f3308e1d132d0333982e8
====================================================================================
Configuration/Tool: pcduino-a10/nsh,CONFIG_ARM_TOOLCHAIN_GNU_EABI
2024-10-20 17:38:10
------------------------------------------------------------------------------------
  Cleaning...
  Configuring...
  Disabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Enabling CONFIG_ARM_TOOLCHAIN_GNU_EABI
  Building NuttX...
arm-none-eabi-ld: warning: /root/nuttx/nuttx has a LOAD segment with RWX permissions
  Normalize pcduino-a10/nsh
====================================================================================
Configuration/Tool: beaglebone-black/lcd,CONFIG_ARM_TOOLCHAIN_GNU_EABI
2024-10-20 17:39:09
```

_What about building a Single Target?_

Suppose we wish to build `ox64:nsh`. Just change this...

```bash
cd nuttx/tools/ci ;
./cibuild.sh -c -A -N -R testlist/$job.dat ;
```

To this...

```bash
cd nuttx ;
tools/configure.sh ox64:nsh ;
make ;
```

# Build NuttX for All Target Groups

_What if we're compiling NuttX for All Target Groups? From `arm-01` to `arm-14`?_

Let's loop through all the Target Groups and compile them...

- For Each Target Group: `arm-01`, `arm-02`, ..., `arm-14`

- Build the Target Group

- Check for Warning and Errors

- Upload the Build Log

TODO: [Here's the CI Output Log](https://gist.github.com/nuttxpr)

Our script becomes more sophisticated:  [run-ci.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh)

```bash
## Run the Build Job, like `arm-01`
function run_job {
  local job=$1
  pushd /tmp
  script $log_file \
    $script_option \
    "$script_dir/run-job.sh $job"
  popd
}

## Search for Errors and Warnings
function find_messages {
  local tmp_file=/tmp/release-tmp.log
  local msg_file=/tmp/release-msg.log
  local pattern='^(.*):(\d+):(\d+):\s+(warning|fatal error|error):\s+(.*)$'
  grep -P "$pattern" $log_file \
    | uniq \
    > $msg_file
  cat $msg_file $log_file >$tmp_file
  mv $tmp_file $log_file
}

## Upload to GitHub Gist
function upload_log {
  local job=$1
  local nuttx_hash=$2
  local apps_hash=$3
  cat $log_file | \
    gh gist create \
    --public \
    --desc "[$job] CI Log for nuttx @ $nuttx_hash / nuttx-apps @ $apps_hash" \
    --filename "ci-$job.log"
}

## Repeat forever for All CI Jobs
for (( ; ; )); do
  for job in \
    arm-01 arm-02 arm-03 arm-04 \
    arm-05 arm-06 arm-07 arm-08 \
    arm-09 arm-10 arm-11 arm-12 \
    arm-13 arm-14
  do
    ## Run the CI Job and find errors / warnings
    run_job $job
    clean_log
    find_messages

    ## Get the hashes for NuttX and Apps
    nuttx_hash=$(grep --only-matching -E "nuttx/tree/[0-9a-z]+" $log_file | grep --only-matching -E "[0-9a-z]+$")
    apps_hash=$(grep --only-matching -E "nuttx-apps/tree/[0-9a-z]+" $log_file | grep --only-matching -E "[0-9a-z]+$")

    ## Upload the log
    upload_log $job $nuttx_hash $apps_hash
    sleep 10
  done
done
```

[(__clean_log__ is here)](TODO)

# Run All CI Jobs

TODO

# Scatter and Gather

TODO

# TODO

```text
https://gist.github.com/nuttxpr

https://docs.docker.com/engine/install/ubuntu/
sudo docker pull \
    ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest

https://lupyuen.github.io/articles/pr#appendix-downloading-the-docker-image-for-nuttx-ci

sudo docker run -it ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest /bin/bash 

root@f38a12771a26:~/nuttx/tools/ci# date ; ./cibuild.sh -c -A -N -R testlist/arm-01.dat ; date
Fri Oct 18 05:58:29 UTC 2024
...
Fri Oct 18 07:24:36 UTC 2024

arm-01: 1 hour 12 mins at GitHub
https://github.com/apache/nuttx/actions/runs/11387572001/job/31692229034

1 hour 26 mins at Ubuntu PC

Intel mac mini
security risk, not docker
firewall

scatter / gather?

https://github.com/apache/nuttx/blob/9c1e0d3d640a297cab9f2bfeedff02f6ce7a8162/.github/gcc.json

^(.*):(\\d+):(\\d+):\\s+(warning|fatal error|error):\\s+(.*)$
```


# What's Next

TODO

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci2.md)

