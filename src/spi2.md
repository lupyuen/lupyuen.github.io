# SPI on Apache NuttX OS

📝 _12 Dec 2021_

![](https://lupyuen.github.io/images/spi2-title.jpg)

TODO

# What's Next

TODO

I'm new to NuttX but I had lots of fun experimenting with it. I hope you'll enjoy NuttX too!

Here are some topics I might explore in future articles, lemme know if I should do these...

-   __SPI Driver__: PineDio Stack BL604 has an onboard LoRa SX1262 Transceiver wired via SPI. Great way to test the NuttX SPI Driver for BL602 / BL604!

    [(More about PineDio Stack BL604)](https://lupyuen.github.io/articles/lorawan2)

-   __LoRaWAN Driver__: Once we get SX1262 talking OK on SPI, we can port the LoRaWAN Driver to NuttX!

    [(LoRaWAN on PineDio Stack BL604)](https://lupyuen.github.io/articles/lorawan2)

-   __Rust__: Porting the Embedded Rust HAL to NuttX sounds really interesting. We might start with GPIO and SPI to see whether the concept is feasible.

(BL602 IoT SDK / FreeRTOS is revamping right now to the [__new "hosal" HAL__](https://twitter.com/MisterTechBlog/status/1456259223323508748). Terrific time to explore NuttX now!)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/spi2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/spi2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1464898624026906625)

TODO1

![](https://lupyuen.github.io/images/spi2-hello.png)

TODO2

![](https://lupyuen.github.io/images/spi2-hello2.png)

TODO3

![](https://lupyuen.github.io/images/spi2-hello3.png)

TODO4

![](https://lupyuen.github.io/images/spi2-hello4.png)

TODO5

![](https://lupyuen.github.io/images/spi2-crash.png)

TODO6

![](https://lupyuen.github.io/images/spi2-debug.png)

TODO7

![](https://lupyuen.github.io/images/spi2-pinedio2.jpg)

TODO8

![](https://lupyuen.github.io/images/spi2-pinedio3.jpg)

TODO9

![](https://lupyuen.github.io/images/spi2-pinedio8.jpg)

TODO10

![](https://lupyuen.github.io/images/spi2-pinedio9.jpg)

TODO11

![](https://lupyuen.github.io/images/spi2-pinedio7.jpg)

TODO12

![](https://lupyuen.github.io/images/spi2-pinedio5.jpg)

TODO13

![](https://lupyuen.github.io/images/spi2-logic4.jpg)

TODO14

![](https://lupyuen.github.io/images/spi2-pinedio6.jpg)

TODO15

![](https://lupyuen.github.io/images/spi2-pinedio.jpg)

TODO16

![](https://lupyuen.github.io/images/spi2-pinedio4.jpg)

TODO17

![](https://lupyuen.github.io/images/spi2-title.jpg)

TODO18

![](https://lupyuen.github.io/images/spi2-pinedio10.jpg)

TODO19

![](https://lupyuen.github.io/images/spi2-app2.png)

TODO20

![](https://lupyuen.github.io/images/spi2-app3.png)

TODO21

![](https://lupyuen.github.io/images/spi2-app4.png)

TODO22

![](https://lupyuen.github.io/images/spi2-crash2.png)

TODO23

![](https://lupyuen.github.io/images/spi2-driver2.png)

TODO24

![](https://lupyuen.github.io/images/spi2-driver3.png)

TODO25

![](https://lupyuen.github.io/images/spi2-driver4.png)

TODO26

![](https://lupyuen.github.io/images/spi2-driver5.png)

TODO27

![](https://lupyuen.github.io/images/spi2-driver6.png)

TODO28

![](https://lupyuen.github.io/images/spi2-driver7.png)

TODO29

![](https://lupyuen.github.io/images/spi2-driver2a.png)

TODO30

![](https://lupyuen.github.io/images/spi2-interface2.png)

TODO31

![](https://lupyuen.github.io/images/spi2-interface3.png)

TODO32

![](https://lupyuen.github.io/images/spi2-interface4.png)

TODO33

![](https://lupyuen.github.io/images/spi2-interface5.png)

TODO34

![](https://lupyuen.github.io/images/spi2-interface6.png)

TODO35

![](https://lupyuen.github.io/images/spi2-interface7.png)

TODO36

![](https://lupyuen.github.io/images/spi2-interface.png)

TODO37

![](https://lupyuen.github.io/images/spi2-logic.png)

TODO38

![](https://lupyuen.github.io/images/spi2-logic2.png)

TODO39

![](https://lupyuen.github.io/images/spi2-logic3.png)

TODO40

![](https://lupyuen.github.io/images/spi2-newapp.png)

TODO41

![](https://lupyuen.github.io/images/spi2-newapp2.png)

TODO42

![](https://lupyuen.github.io/images/spi2-newapp3.png)

TODO43

![](https://lupyuen.github.io/images/spi2-newapp4.png)

TODO44

![](https://lupyuen.github.io/images/spi2-newapp5.png)

TODO45

![](https://lupyuen.github.io/images/spi2-newdriver.png)

TODO46

![](https://lupyuen.github.io/images/spi2-newdriver10.png)

TODO47

![](https://lupyuen.github.io/images/spi2-newdriver2.png)

TODO48

![](https://lupyuen.github.io/images/spi2-newdriver3.png)

TODO49

![](https://lupyuen.github.io/images/spi2-newdriver4.png)

TODO50

![](https://lupyuen.github.io/images/spi2-newdriver5.png)

TODO51

![](https://lupyuen.github.io/images/spi2-newdriver6.png)

TODO52

![](https://lupyuen.github.io/images/spi2-newdriver9.png)

TODO53

![](https://lupyuen.github.io/images/spi2-pinedio.png)

TODO54

![](https://lupyuen.github.io/images/spi2-pinedio2.png)

TODO55

![](https://lupyuen.github.io/images/spi2-pinedio3.png)

TODO56

![](https://lupyuen.github.io/images/spi2-script.png)

TODO57

![](https://lupyuen.github.io/images/spi2-sx.png)

TODO58

![](https://lupyuen.github.io/images/spi2-sx2.png)

TODO59

![](https://lupyuen.github.io/images/spi2-sx3.png)

TODO60

![](https://lupyuen.github.io/images/spi2-sx4.png)

TODO61

![](https://lupyuen.github.io/images/spi2-sx5.png)

TODO62

![](https://lupyuen.github.io/images/spi2-sx6.png)

TODO63

![](https://lupyuen.github.io/images/spi2-sx7.png)
