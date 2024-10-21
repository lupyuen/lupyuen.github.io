# Your very own Build Farm for Apache NuttX RTOS

📝 _20 Nov 2024_

![TODO](https://lupyuen.github.io/images/ci2-title.jpg)

[__Refurbished Ubuntu PCs__](TODO) have become quite affordable ($??? pic above). What if we could turn them into a __(Low-Cost) Build Farm__ for [__Apache NuttX RTOS__](TODO)?

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
- [run-ci.sh](https://github.com/lupyuen/nuttx-release/blob/main/run-ci.sh) looping forever through `arm-01` to `arm-14`, running the job, searching for errors and uploading the logs

# What's Next

TODO

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ci2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci2.md)

