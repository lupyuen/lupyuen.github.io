# Your very own Build Farm for Apache NuttX RTOS

📝 _20 Nov 2024_

![TODO](https://lupyuen.github.io/images/ci2-title.jpg)

[__Refurbished Ubuntu PCs__](TODO) have become quite affordable ($??? pic above). What if we could turn them into a __(Low-Cost) Build Farm__ for [__Apache NuttX RTOS__](TODO)?

TODO

# Run A Single CI Job

TODO

_What if we could run the CI Jobs on our own Ubuntu PCs? Without any help from GitHub Actions?_

I'm experimenting with a "Build Farm" at home (refurbished PC) that __runs NuttX CI Jobs all day__ non-stop 24 x 7:
- Check out `master` branch of `nuttx`, run CI Job `arm-01`
- Wait for `arm-01` to complete (roughly 1.5 hours)
- Check out `master` branch of `nuttx`, run CI Job `arm-02`
- Wait for `arm-02` to complete (roughly 1.5 hours)
- Do the same until `arm-14`, then loop back to `arm-01`
- [Here's the CI Output Log](https://gist.github.com/nuttxpr)

How does it work?
- [run-job.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-job.sh) will run a single CI Job, by calling the NuttX Docker Image, which is called by...

```bash
#!/usr/bin/env bash
## Run a NuttX CI Job with Docker

echo Now running https://github.com/lupyuen/nuttx-release/blob/main/run-job.sh
echo Called by https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh
set -x  ## Echo commands

# Parameter is CI Job, like "arm-01"
job=$1

## Show the System Info
neofetch
sleep 10

## Download the Docker Image
sudo docker pull \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest
sleep 10

## Run the CI in Docker Container
sudo docker run -it \
  ghcr.io/apache/nuttx/apache-nuttx-ci-linux:latest \
  /bin/bash -c "
  cd ;
  pwd ;
  git clone https://github.com/apache/nuttx ;
  git clone https://github.com/apache/nuttx-apps apps ;
  pushd nuttx ; echo NuttX Source: https://github.com/apache/nuttx/tree/\$(git rev-parse HEAD) ; popd ;
  pushd apps  ; echo NuttX Apps: https://github.com/apache/nuttx-apps/tree/\$(git rev-parse HEAD) ; popd ;
  sleep 10 ;
  cd nuttx/tools/ci ;
  ./cibuild.sh -c -A -N -R testlist/$job.dat ;
"
```

- [run-ci.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh) looping forever through `arm-01` to `arm-14`, running the job, searching for errors and uploading the logs

```bash
#!/usr/bin/env bash
## Run NuttX CI with Docker

echo Now running https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh
set -x  ## Echo commands
device=ci

## Get the Script Directory
script_path="${BASH_SOURCE}"
script_dir="$(cd -P "$(dirname -- "${script_path}")" >/dev/null 2>&1 && pwd)"
log_file=/tmp/release-$device.log

## Get the `script` option
if [ "`uname`" == "Linux" ]; then
  script_option=-c
else
  script_option=
fi

## Run the job
function run_job {
  local job=$1
  pushd /tmp
  script $log_file \
    $script_option \
    "$script_dir/run-job.sh $job"
  popd
}

## Strip the control chars
function clean_log {
  local tmp_file=/tmp/release-tmp.log
  cat $log_file \
    | tr -d '\r' \
    | tr -d '\r' \
    | sed 's/\x08/ /g' \
    | sed 's/\x1B(B//g' \
    | sed 's/\x1B\[K//g' \
    | sed 's/\x1B[<=>]//g' \
    | sed 's/\x1B\[[0-9:;<=>?]*[!]*[A-Za-z]//g' \
    | sed 's/\x1B[@A-Z\\\]^_]\|\x1B\[[0-9:;<=>?]*[-!"#$%&'"'"'()*+,.\/]*[][\\@A-Z^_`a-z{|}~]//g' \
    >$tmp_file
  mv $tmp_file $log_file
  echo ----- "Done! $log_file"
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

