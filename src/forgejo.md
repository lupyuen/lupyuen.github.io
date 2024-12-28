# TODO Forgejo

📝 _31 Jan 2024_

![TODO](https://lupyuen.github.io/images/forgejo-title.jpg)

__Life Without GitHub:__ What's it like?

_Why are we doing this?_

- __GitHub is Blocked__ in some parts of the world

- Some devs prefer not to __collaborate on GitHub__ _(ethical / other reasons)_

- Can we make NuttX Community a little more inclusive? By hosting our __Git Forge outside GitHub__?

- Also: We're hitting some [__Budget Limits__](TODO) at GitHub

TODO

# GitHub Migration: 2 Ways

- __NuttX Mirror__: Auto-sync by Forgejo (e.g. every hour)

  No migration of PRs and Issues

- __NuttX Update__: Manual-sync by our script

  Possible to migrate PRs and Issues (but ran into problems)

# Install

TODO: forgejo-install1.png

![TODO](https://lupyuen.github.io/images/forgejo-install1.png)

TODO: forgejo-install2.png

![TODO](https://lupyuen.github.io/images/forgejo-install2.png)

TODO: forgejo-install3.png

![TODO](https://lupyuen.github.io/images/forgejo-install3.png)

# Mirror

TODO: forgejo-mirror1.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror1.png)

TODO: forgejo-mirror2.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror2.png)

TODO: forgejo-mirror3.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror3.png)

TODO: forgejo-mirror4.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror4.png)

TODO: forgejo-mirror5.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror5.png)

TODO: forgejo-mirror6.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror6.png)

TODO: forgejo-mirror7.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror7.png)

TODO: forgejo-mirror8.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror8.png)

TODO: forgejo-mirror9.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror9.png)

TODO: forgejo-mirror10.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror10.png)

TODO: forgejo-mirror11.png

![TODO](https://lupyuen.github.io/images/forgejo-mirror11.png)

TODO: forgejo-mirror12.png


# Update

![TODO](https://lupyuen.github.io/images/forgejo-mirror12.png)

TODO: forgejo-update1.png

![TODO](https://lupyuen.github.io/images/forgejo-update1.png)

TODO: forgejo-update2.png

![TODO](https://lupyuen.github.io/images/forgejo-update2.png)

TODO: forgejo-update3.png

![TODO](https://lupyuen.github.io/images/forgejo-update3.png)

TODO: forgejo-update4.png

![TODO](https://lupyuen.github.io/images/forgejo-update4.png)

TODO: forgejo-update5.png

![TODO](https://lupyuen.github.io/images/forgejo-update5.png)

TODO: forgejo-update6.png

![TODO](https://lupyuen.github.io/images/forgejo-update6.png)

TODO: forgejo-update7.png

![TODO](https://lupyuen.github.io/images/forgejo-update7.png)

TODO: forgejo-update8.png

![TODO](https://lupyuen.github.io/images/forgejo-update8.png)

TODO: forgejo-update9.png

![TODO](https://lupyuen.github.io/images/forgejo-update9.png)


# Home

TODO: forgejo-home.png

![TODO](https://lupyuen.github.io/images/forgejo-home.png)

TODO: forgejo-home2.png

![TODO](https://lupyuen.github.io/images/forgejo-home2.png)

# PR


TODO: forgejo-pr1.png

![TODO](https://lupyuen.github.io/images/forgejo-pr1.png)

TODO: forgejo-pr2.png

![TODO](https://lupyuen.github.io/images/forgejo-pr2.png)

TODO: forgejo-pr3.png

![TODO](https://lupyuen.github.io/images/forgejo-pr3.png)

TODO: forgejo-pr4.png

![TODO](https://lupyuen.github.io/images/forgejo-pr4.png)

TODO: forgejo-pr5.png

![TODO](https://lupyuen.github.io/images/forgejo-pr5.png)

TODO: forgejo-pr6.png

![TODO](https://lupyuen.github.io/images/forgejo-pr6.png)

TODO: forgejo-pr7.png

![TODO](https://lupyuen.github.io/images/forgejo-pr7.png)

# Actions

TODO: forgejo-actions1.png

![TODO](https://lupyuen.github.io/images/forgejo-actions1.png)

TODO: forgejo-commits.png

![TODO](https://lupyuen.github.io/images/forgejo-commits.png)

# SSH

TODO: forgejo-ssh.png

![TODO](https://lupyuen.github.io/images/forgejo-ssh.png)

TODO: forgejo-ssh2.png

![TODO](https://lupyuen.github.io/images/forgejo-ssh2.png)


# TODO

```text
https://forgejo.org/docs/latest/admin/installation-docker/

docker pull codeberg.org/forgejo/forgejo:9
cd $HOME
git clone https://github.com/lupyuen/nuttx-forgejo
cd nuttx-forgejo

docker-compose.yml:
<<
services:
  server:
    volumes:
      - forgejo-data:/data

volumes:
  forgejo-data:
>>

## TODO: Is `sudo` needed?
sudo docker compose up

## If It Quits To Command-Line:
## Run a second time to get it up
sudo docker compose up

to down: sudo docker compose down
https://gist.github.com/lupyuen/efdd2db49e2d333bc7058194d78cd846

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

# Change the Default Page

```text
/data/gitea/conf/app.ini

sudo docker cp \
  forgejo:/data/gitea/conf/app.ini \
  .

Edit app.init
https://forgejo.org/docs/latest/admin/config-cheat-sheet/#server-server
<<
[server]
LANDING_PAGE = explore
>>

sudo docker cp \
  app.ini \
  forgejo:/data/gitea/conf/app.ini
sudo docker compose down
sudo docker compose up
```

Looks more sensible

# Test SSH Key

TODO: SSH Port not exposed for security reasons

```text
ssh-keygen -t ed25519 -a 100
Call it ~/.ssh/nuttx-forge

Edit $HOME/.ssh/config
<<
Host nuttx-forge
  HostName localhost
  Port 222
  IdentityFile ~/.ssh/nuttx-forge
>>
(localhost will change to the future external IP)

Settings > SSH Keys
Paste ~/.ssh/nuttx-forge.pub
Click Add Key

$ ssh -T git@nuttx-forge  

Hi there, nuttx! You've successfully authenticated with the key named nuttx-forge (luppy@5ce91ef07f94), but Forgejo does not provide shell access.
If this is unexpected, please log in with password and setup Forgejo under another user.
```

# Use SSH Key

```text
git clone git@nuttx-forge:nuttx/test.git
cd test
echo Testing >test.txt
git add .
git commit --all --message="Test Commit"
git push -u origin main
```

# Sync Mirror to Update

TODO: Requires SSH Access, to work around the password

https://github.com/lupyuen/nuttx-forgejo/blob/main/sync-mirror-to-update.sh

```text
./sync-mirror-to-update.sh
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/3afe37d47933d17b8646b3c9de12f17d)

If they go out of sync: Hard-Revert the Downstream Commits in Read-Write Mirror of NuttX Repo

```bash
## Repeat for all conflicting commits
$ git reset --hard HEAD~1

HEAD is now at 7d6b2e48044 gcov/script: gcov.sh is implemented using Python
➜  downstream git:(master) $ git status

On branch master
Your branch is behind 'origin/master' by 1 commit, and can be fast-forwarded.
  (use "git pull" to update your local branch)

nothing to commit, working tree clean
➜  downstream git:(master) $ git push -f

Total 0 (delta 0), reused 0 (delta 0), pack-reused 0
To nuttx-forge:nuttx/nuttx-update
 + e26e8bda0e9...7d6b2e48044 master -> master (forced update)
```

TODO: [sync-mirror-to-update.sh](https://github.com/lupyuen/nuttx-forgejo/blob/main/sync-mirror-to-update.sh)

```bash
#!/usr/bin/env bash
## Sync the Git Commits from NuttX Mirror Repo to NuttX Update Repo

set -e  ## Exit when any command fails
set -x  ## Echo commands

## Checkout the Upstream and Downstream Repos
tmp_dir=/tmp/sync-mirror-to-update
rm -rf $tmp_dir
mkdir $tmp_dir
cd $tmp_dir
git clone git@nuttx-forge:nuttx/nuttx-mirror upstream
git clone git@nuttx-forge:nuttx/nuttx-update downstream

## Find the First Commit to Sync
set +x ; echo "**** Last Upstream Commit" ; set -x
pushd upstream
upstream_commit=$(git rev-parse HEAD)
git --no-pager log -1
popd
set +x ; echo "**** Last Downstream Commit" ; set -x
pushd downstream
downstream_commit=$(git rev-parse HEAD)
git --no-pager log -1
popd

## If no new Commits to Sync: Quit
if [[ "$downstream_commit" == "$upstream_commit" ]]; then
  set +x ; echo "**** No New Commits to Sync" ; set -x
  exit
fi

## Apply the Upstream Commits to Downstream Repo
pushd downstream
git pull git@nuttx-forge:nuttx/nuttx-mirror master
git status
popd

## Commit the Patched Downstream Repo
pushd downstream
git push -f
popd

## Verify that Upstream and Downstream Commits are identical
set +x ; echo "**** Updated Downstream Commit" ; set -x
pushd downstream
git pull
downstream_commit2=$(git rev-parse HEAD)
git --no-pager log -1
popd

## If Not Identical: We have a problem
if [[ "$downstream_commit2" != "$upstream_commit" ]]; then
  set +x ; echo "**** Sync Failed: Upstream and Downstream Commits don't match!" ; set -x
  exit 1
fi

set +x ; echo "**** Done!" ; set -x
```

# Backup Forgejo

```text
sudo docker exec \
  -it \
  forgejo \
  /bin/bash -c \
  "tar cvf /tmp/data.tar /data"

sudo docker cp \
  forgejo:/tmp/data.tar \
  .
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/d151537dc79dc9b2ecafc4c2620b28bb)

# SSH Fails with Local Filesystem

```text
ssh -T -p 222 git@localhost

forgejo  | Authentication refused: bad ownership or modes for file /data/git/.ssh/authorized_keys
forgejo  | Connection closed by authenticating user git 172.22.0.1 port 47768 [preauth]
forgejo  | Authentication refused: bad ownership or modes for file /data/git/.ssh/authorized_keys
forgejo  | Connection closed by authenticating user git 172.22.0.1 port 40328 [preauth]
forgejo  | Authentication refused: bad ownership or modes for file /data/git/.ssh/authorized_keys
forgejo  | Connection closed by authenticating user git 172.22.0.1 port 39114 [preauth]

ls -ld $HOME/nuttx-forgejo/forgejo/git/.ssh                
drwx------@ 4 luppy  staff  128 Dec 20 13:45 /Users/luppy/nuttx-forgejo/forgejo/git/.ssh

$ ls -l $HOME/nuttx-forgejo/forgejo/git/.ssh/authorized_keys 
-rw-------@ 1 luppy  staff  279 Dec 21 11:13 /Users/luppy/nuttx-forgejo/forgejo/git/.ssh/authorized_keys

sudo docker exec \
  -it \
  forgejo \
  /bin/bash

User ID should be git, not 501! (Some kinda jeans?)
5473c234c7eb:/data/git# ls -ld /data/git/.ssh
drwx------    1 501      dialout        128 Dec 20 13:45 /data/git/.ssh
5473c234c7eb:/data/git# ls -l /data/git/.ssh/authorized_keys
-rw-------    1 501      dialout        279 Dec 21 11:13 /data/git/.ssh/authorized_keys
5473c234c7eb:/data/git#

Won't work:
exec su-exec root chown -R git /data/git/.ssh
```

# What's Next

TODO

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
