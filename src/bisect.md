# TODO (Git Bisect)

📝 _31 Jan 2024_

![TODO](https://lupyuen.github.io/images/bisect-title.jpg)

TODO

# TODO

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

Bisect run
If you have a script that can tell if the current source code is good or bad, you can bisect by issuing the command:

$ git bisect run my_script arguments

Note that the script (my_script in the above example) should exit with code 0 if the current source code is good/old, and exit with a code between 1 and 127 (inclusive), except 125, if the current source code is bad/new.

Any other exit code will abort the bisect process. It should be noted that a program that terminates via exit(-1) leaves $? = 255, (see the exit(3) manual page), as the value is chopped with & 0377.

The special exit code 125 should be used when the current source code cannot be tested. If the script exits with this code, the current revision will be skipped (see git bisect skip above). 125 was chosen as the highest sensible value to use for this purpose, because 126 and 127 are used by POSIX shells to signal specific error status (127 is for command not found, 126 is for command found but not executable—​these details do not matter, as they are normal errors in the script, as far as bisect run is concerned).

You may often find that during a bisect session you want to have temporary modifications (e.g. s/#define DEBUG 0/#define DEBUG 1/ in a header file, or "revision that does not have this commit needs this patch applied to work around another problem this bisection is not interested in") applied to the revision being tested.

To cope with such a situation, after the inner git bisect finds the next revision to test, the script can apply the patch before compiling, run the real test, and afterwards decide if the revision (possibly with the needed patch) passed the test and then rewind the tree to the pristine state. Finally the script should exit with the status of the real test to let the git bisect run command loop determine the eventual outcome of the bisect session.

[rv-virt:citest fails with Load Access Fault at ltp_interfaces_pthread_barrierattr_init_2_1 (risc-v-05)](https://github.com/apache/nuttx/issues/15170)

[arch/toolchain: Add toolchain gcc](https://github.com/apache/nuttx/pull/14779)

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
