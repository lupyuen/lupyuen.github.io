# TODO Forgejo

📝 _31 Jan 2024_

![TODO](https://lupyuen.github.io/images/bisect-title.jpg)

__Life Without GitHub:__ What's it like?

_Why are we doing this?_

- __GitHub is Blocked__ in some parts of the world

- Some devs prefer not to __collaborate on GitHub__ _(ethical / other reasons)_

- Can we make NuttX Community a little more inclusive? By hosting our __Git Forge outside GitHub__?

- Also: We're hitting some [__Budget Limits__](TODO) at GitHub

TODO

# TODO

```text
https://forgejo.org/docs/latest/admin/installation-docker/

docker pull codeberg.org/forgejo/forgejo:9
cd $HOME
git clone https://github.com/lupyuen/nuttx-forgejo
cd nuttx-forgejo

## TODO: Is `sudo` needed?
sudo docker compose up

## If It Quits To Command-Line:
## Run a second time to get it up
sudo docker compose up

to down: sudo docker compose down
https://gist.github.com/lupyuen/8438ef716f428606d3913f7bc8efc0b7

Will auto create `forgejo` folder
Browse to http://localhost:3002/
SQLite, upgrade to PostgreSQL later
Domain: nuttx-forge.org
Create admin user: nuttx

(For CloudFlare Tunnel: Set __Security > Settings > High__)

+ > New Migration > GitHub
This repo will be a mirror
access token
nuttx-mirror
Migrate Repo

Settings > Repository > Mirror Settings
Mirror interval
1h
Update Mirror Settings

Create Issue
Actions: No Runner
View Commit

+ > New Migration > GitHub
access token
select labels, milestones, releases
don't select PR, it will run forever!
don't select issues: "comment references non existent Issuelndex 1"
nuttx-update
Migrate Repo

JavaScript promise rejection: Failed to fetch. Open browser console to see more details. (2)
ignore

Fun to watch the sync from nuttx

```

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
