# Continuous Integration Dashboard for Apache NuttX RTOS

📝 _30 Nov 2024_

![Continuous Integration Dashboard for Apache NuttX RTOS](https://lupyuen.github.io/images/ci4-title.jpg)

TODO

# Build Score

TODO

| Score | Status | Example |
|:-----:|:-------|:--------|
| 0.0 | Error | TODO
| 0.5 | Warning | TODO
| 0.8 | Unknown | TODO
| 1.0 | Success | TODO

Examples

Metric per Target and Source

Why Pull not Push?

Multple Values

Remove Duplicates

# Grafana Dashboard

TODO

Create a simple dashboard

Assume Build Score already set up

```bash
brew install grafana
brew services start grafana
http://localhost:3000
```

TODO: ci4-grafana1.png

![TODO](https://lupyuen.github.io/images/ci4-grafana1.png)

TODO: ci4-grafana2.png

![TODO](https://lupyuen.github.io/images/ci4-grafana2.png)

TODO: ci4-grafana3.png

![TODO](https://lupyuen.github.io/images/ci4-grafana3.png)

TODO: ci4-grafana4.png

![TODO](https://lupyuen.github.io/images/ci4-grafana4.png)

TODO: ci4-grafana5.png

![TODO](https://lupyuen.github.io/images/ci4-grafana5.png)

TODO: ci4-grafana6.png

![TODO](https://lupyuen.github.io/images/ci4-grafana6.png)

TODO: ci4-grafana7.png

![TODO](https://lupyuen.github.io/images/ci4-grafana7.png)

TODO: ci4-grafana8.png

![TODO](https://lupyuen.github.io/images/ci4-grafana8.png)

TODO: ci4-grafana9.png

![TODO](https://lupyuen.github.io/images/ci4-grafana9.png)

TODO: ci4-grafana10.png

![TODO](https://lupyuen.github.io/images/ci4-grafana10.png)

# Prometheus Setup

TODO

HTTP Request

Nowhere to pull

So pull from Pushgateway

We push to Pushgateway

OK to push latest data twice

OK to push from multiple PCs, they are distinct

```bash
brew install prometheus
brew services start prometheus
http://localhost:9090
admin for username and password

brew install go
git clone https://github.com/prometheus/pushgateway
cd pushgateway
go run main.go
http://localhost:9091

cat <<EOF | curl --data-binary @- http://localhost:9091/metrics/job/nuttxpr/instance/milkv_duos:nsh
# TYPE build_score gauge
# HELP build_score 1.0 for successful build, 0.0 for failed build
build_score{ url="http://bbb", msg="warning: bbb" } 0.7
EOF
```

# Ingest the Build Logs

TODO

Rust App

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

[__lupyuen.github.io/src/ci4.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ci4.md)
