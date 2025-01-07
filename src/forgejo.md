# Forgejo Git Forge for Apache NuttX RTOS (Experimental)

📝 _31 Jan 2025_

![TODO](https://lupyuen.github.io/images/forgejo-title.jpg)

__Life Without GitHub:__ What's it like? Today we talk about [__Forgejo Git Forge__](TODO), and whether [__Apache NuttX RTOS__](TODO) could possibly switch from GitHub to our own Git Forge.

_What's this Forgejo? And why is it a "Git Forge"?_

Think GitHub... But __Open-Source__ and __Self-Hosted__! _(GoLang Web + PostgreSQL Database)_

[__Forgejo__](TODO) is a __Git Forge__, the server code that will publicly host and share a Git Repo. _(Including our NuttX Repo)_

_Why explore Forgejo for NuttX?_

- If GitHub breaks: What's our __Contingency Plan__?

- __GitHub is Blocked__ in some parts of the world...

- Can we __Mirror NuttX Repo__ outside GitHub? So NuttX Community becomes more inclusive?

- Also: We're hitting [__Budget Limits__](TODO) at GitHub, might need alternatives

TODO: Pic of NuttX on Forgejo

# NuttX On Forgejo

_Installing our own Git Forge: Is it easy?_

Yep! Here's our experiment of __NuttX on Forgejo__...

- [__`https://nuttx-forge.org`__](https://nuttx-forge.org/explore/repos?q=&only_show_relevant=false&sort=moststars)

Installing our __Forgejo Server__ was plain-sailing (especially on Docker)

- TODO: Appendix

- Thanks to the excellent [__Forejo Docs__](TODO)

Our Git Forge is running on [__Plain Old SQLite__](TODO) database. Later we might [__Upgrade to PostgreSQL__](TODO).

# Works The Same

_Is it easy to use our own Git Forge?_

Yes Forgejo is pleasantly __Gittish-Hubbish__. Inside Forgejo: __Pull Requests__ and __Issues__ look familiar...

TODO: Pic of Pull Requests and Issues

[(About Forgejo __Pull Requests__)](TODO)

[(About Forgejo __Issues__)](TODO)

Forgejo is fully compatible with our __Git Command-Line Tools__ (and VSCode)

```bash
## Download the NuttX Mirror Repo
## From our Forgejo Server
git clone \
  https://nuttx-forge.org/nuttx/nuttx-mirror

## Also works for SSH (instead of HTTPS)
## But SSH isn't enabled on our server
git clone \
  git@nuttx-forge.org:nuttx/nuttx-mirror
```

_Haven't we seen this somewhere?_

- [__Codeberg__](TODO) is powered by Forgejo

- [__GitLab__](TODO) runs on Gitea, which is the [__predecessor of Forgejo__](https://forgejo.org/compare-to-gitea/)

- BTW: __FreeBSD Project__ is [__moving to Forgejo__](TODO)

# Coexist With GitHub

_Will our Git Forge coexist with GitHub?_

Ah now it gets tricky. Ideally we should allow GitHub to coexist with our Git Forge, synced both ways...

- __NuttX Repo__ at GitHub shall __sync down regularly__ to Our Git Forge

  (So NuttX Devs can pull updates if GitHub breaks)

- __Pull Requests__ at our Git Forge shall be __pushed up to NuttX Repo__ at GitHub

  (So Local Changes in our Git Forge can be synced back)

Forgejo works great for syncing NuttX Repo from GitHub. We configured Forgejo to __auto-sync from GitHub every hour__...

TODO: Pic of repo sync from GitHub

TODO: Pic of commits

Oops this creates a [__Read-Only Mirror__](TODO) that won't allow __Pull Requests__!

TODO: Pic of read-only mirror

Thus we created our own [__Read-Write Mirror__](TODO) of NuttX Repo. Forgejo won't auto-sync this repo, hence we wrote our own __Syncing Script__ (that works without GitHub)...

TODO: Pic of read-write mirror

TODO: Sync script

TODO: Pic of PR sync

_But Pull Requests shall be synced back to GitHub?_

Indeed, we'll probably call GitHub API to send the __Pull Requests back to GitHub__.

With this setup, we can't allow Pull Requests to be locally merged at Forgejo. Instead, Pull Requests shall be __merged at GitHub__. Then Forgejo shall auto-sync the updates into our Git Forge.

# Continuous Integration

_Will our Git Forge run CI Checks on Pull Requests?_

__GitHub Actions CI__ (Continuous Integration) becomes a Sticky Issue with Forgejo...

- Forgejo will import __GitHub Actions Workflows__ and execute them

  TODO: Pic of Forgejo with GitHub Actions Workflow

- But we don't have a __Secure CI Server__ to execute the CI Workflow!

- Some GitHub Workflows are [__Not Supported__](TODO): arch.yml (NuttX Build Rules)

_Why do we need a Secure CI Server?_

During PR Submission: Our CI Workflow might need to execute the __scripts and code submitted__ by NuttX Devs.

If we don't secure our CI Server, we might create [__Security Problems__](TODO) in our server.

Securing our CI Server is probably the toughest part of our Git Forge Migration. (That's why GitHub is so expensive!)

# Sync our Read-Write Mirror

_Forgejo won't Auto-Sync our Read-Write Mirror. How do we sync it?_

We run a script to __Sync the Git Commits__...

- From our __Read-Only Mirror__ [__`nuttx-mirror`__](TODO)

- To the __Read-Write Mirror__ [__`nuttx-update`__](TODO)

- So it will work even when GitHub breaks

```bash
## Sync Once: From Read-Only Mirror to Read-Write Mirror
git clone https://github.com/lupyuen/nuttx-forgejo
cd nuttx-forgejo
./sync-mirror-to-update.sh

## Or to Sync Periodically
## ./run.sh
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/3afe37d47933d17b8646b3c9de12f17d)

__Commit History__ shall be 100% identical. Including the __Commit Hashes__!

Our script works like this: [sync-mirror-to-update.sh](https://github.com/lupyuen/nuttx-forgejo/blob/main/sync-mirror-to-update.sh)

```bash
## Sync the Git Commits
## From our Read-Only Mirror Repo (nuttx-mirror)
## To the Read-Write Mirror Repo (nuttx-update)
set -e  ## Exit when any command fails

## Checkout the Upstream and Downstream Repos
tmp_dir=/tmp/sync-mirror-to-update
rm -rf $tmp_dir
mkdir $tmp_dir
cd $tmp_dir
git clone git@nuttx-forge:nuttx/nuttx-mirror upstream
git clone git@nuttx-forge:nuttx/nuttx-update downstream

## Find the First Commit to Sync
pushd upstream
upstream_commit=$(git rev-parse HEAD)
git --no-pager log -1
popd
pushd downstream
downstream_commit=$(git rev-parse HEAD)
git --no-pager log -1
popd

## If no new Commits to Sync: Quit
if [[ "$downstream_commit" == "$upstream_commit" ]]; then
  echo "No New Commits to Sync" ; exit
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
echo "Updated Downstream Commit"
pushd downstream
git pull
downstream_commit2=$(git rev-parse HEAD)
git --no-pager log -1
popd

## If Not Identical: We have a problem
if [[ "$downstream_commit2" != "$upstream_commit" ]]; then
  echo "Sync Failed: Upstream and Downstream Commits don't match!" ; exit 1
fi
```

_What if we accidentally Merge a PR? And our Read-Write Mirror goes out of sync?_

If our Read-Write Mirror goes out of sync: We __Hard-Revert the Commits__ in the Read-Write Mirror. To keep it in sync with the Read-Only Mirror again...

```bash
## Repeat for all conflicting commits...
$ git reset --hard HEAD~1
HEAD is now at 7d6b2e48044 gcov/script: gcov.sh is implemented using Python

## We have reverted one commit
$ git status
Your branch is behind 'origin/master' by 1 commit, and can be fast-forwarded.

## Push it to the repo
$ git push -f
To nuttx-forge:nuttx/nuttx-update
e26e8bda0e9...7d6b2e48044 master -> master (forced update)
```

_What if we really need to Accept Pull Requests in our Read-Write Mirror?_

TODO

| | |
|:---:|:---:|
| [__`nuttx-mirror`__](TODO) | [__`nuttx-update`__](TODO)
| __Read-Only Mirror__ |  __Read-Write Mirror__
| Auto-Sync by Forgejo <br> (every hour) | Manual-Sync by our script
| Can't migrate PRs and Issues | Can migrate PRs and Issues <br> (but ran into problems)
| Can't create PRs | Can create PRs

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

[__lupyuen.org/src/forgejo.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/forgejo.md)

# Appendix: Install our Forgejo Server

Here are the steps to install our own __Forgejo Server__ on __Docker Engine__...

[(Derived from __Official Docs__)](https://forgejo.org/docs/latest/admin/installation-docker/)

[(Tested on __macOS Rancher Desktop__)](TODO)

```bash
## Download the Forgejo Docker Image
## And our Modified Docker Compose Config
docker pull codeberg.org/forgejo/forgejo:9
cd $HOME
git clone https://github.com/lupyuen/nuttx-forgejo
cd nuttx-forgejo

## docker-compose.yml: Points to `forgejo-data` as the Data Volume (instead of Local Filesystem)
## Because Rancher Desktop won't set permissions correctly for Local Filesystem (see secton below)
## services:
##   server:
##     volumes:
##       - forgejo-data:/data
## volumes:
##   forgejo-data:

## Up the Forgejo Server
## (Is `sudo` needed?)
sudo docker compose up

## If It Quits To Command-Line:
## Run a second time to get it up
sudo docker compose up

## If we need to down the Forgejo Server:
## sudo docker compose down
```

[(See the __Install Log__)](https://gist.github.com/lupyuen/efdd2db49e2d333bc7058194d78cd846)

- This will auto-create the __`forgejo`__ folder for Forgejo Data

- We browse to __`http://localhost:3002`__

- Select __SQLite__ as the database (we upgrade to PostgreSQL later)

- Set __Domain__ to __`nuttx-forge.org`__ (or your domain)

- Create an __Admin User__ named __`nuttx`__ (or your preference)

- Talk to our __Web Hosting Provider__ (or Tunnel Provider).

  Channel all Incoming Requests for _https://nuttx-forge.org_
    
  To _http://YOUR\_DOCKER\_MACHINE:3002_

  (__HTTPS Port 443__ connects to __HTTP Port 3002__ via Reverse Proxy)

  (For CloudFlare Tunnel: Set __Security > Settings > Low__)

  (Change _nuttx-forge.org_ to Your Domain Name)

- Remember to __Backup Forgejo__ regularly!

  ```text
  ## Inside Docker: Amalgamate the `/data` folder into `/tmp/data.tar`
  sudo docker exec \
    -it \
    forgejo \
    /bin/bash -c \
    "tar cvf /tmp/data.tar /data"

  ## Copy `/tmp/data.tar` out from Docker
  sudo docker cp \
    forgejo:/tmp/data.tar \
    .
  ```

  [(See the __Backup Log__)](https://gist.github.com/lupyuen/d151537dc79dc9b2ecafc4c2620b28bb)

Back to the __Forgejo Configuration__: This is how we specify the __Forgejo Database__...

![TODO](https://lupyuen.github.io/images/forgejo-install1.png)

And the __Server Domain__...

![TODO](https://lupyuen.github.io/images/forgejo-install2.png)

Finally our __Admin User__...

![TODO](https://lupyuen.github.io/images/forgejo-install3.png)

_Forgejo's Default Page: How to change it?_

TODO: Change the Default Page

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

TODO: forgejo-home.png

![TODO](https://lupyuen.github.io/images/forgejo-home.png)

TODO: forgejo-home2.png

![TODO](https://lupyuen.github.io/images/forgejo-home2.png)

# Appendix: Read-Only Mirror

Now that Forgejo is up: Let's create a __Read-Only Mirror__ of the NuttX Repo at GitHub. 

Forgejo shall __auto-sync our repo__ (every hour), but it __won't allow Pull Requests__ in our Read-Only Mirror...

1.  At Top Right: Select __`+` > New Migration__

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror1.png)

1.  Select __GitHub__

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror2.png)

1.  Enter the __GitHub URL__ of NuttX Repo

    Fill in the __Access Token__

    Check __"This Repo Will Be A Mirror"__, __Migrate LFS Files__ and __Wiki__

    Set the __Repo Name__ to __`nuttx-mirror`__

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror3.png)

1.  This will create a __Read-Only Mirror__...

    Forgejo __won't migrate__ the other items: Issues, Pull Requests, Labels, Milestones, Releases (pic above)

    (Read-Write Mirror will be more useful, see the next section)

1.  And Forgejo dutifully creates our __Read-Only Mirror__!

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror4.png)

1.  By Default: Forgejo __syncs every 8 hours__. We change the Mirror Interval to __1 hour__

    (Settings > Repository > Mirror Settings)

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror5.png)

1.  Forgejo has helpfully migrated our __Template for NuttX Issues__

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror6.png)

1.  Forgejo has ported over our __GitHub Actions Workflows__. But they won't run because we don't have a __CI Server__ for Ubuntu.

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror7.png)

1.  __NuttX Commits__ look very familiar in Forgejo

    __Commit Hashes__ are identical to GitHub

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror8.png)

1.  So cool to watch Forgejo __Auto-Sync our GitHub Repo__

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror9.png)

1.  Auto-Sync may trigger __CI Workflows__. But we don't have CI Servers to run them (yet).

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror11.png)

1.  That's why the __CI Jobs will wait forever__

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror12.png)

1.  __Git Command-Line Tools__ will work great with our Forgejo Server

    ```bash
    ## Download the NuttX Mirror Repo
    ## From our Forgejo Server
    git clone \
      https://nuttx-forge.org/nuttx/nuttx-mirror

    ## Also works for SSH (instead of HTTPS)
    ## But SSH isn't enabled on our server
    git clone \
      git@nuttx-forge.org:nuttx/nuttx-mirror
    ```

# Appendix: Read-Write Mirror

Earlier we created a Read-Only Mirror. But it doesn't allow Pull Requests!

Now we create a __Read-Write Mirror__ of the NuttX Repo at GitHub, which will allow Pull Requests. Forgejo __won't auto-sync__ our repo, instead we'll run a script to sync the repo...

1.  At Top Right: Select __`+` > New Migration__

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror1.png)

1.  Select __GitHub__

    ![TODO](https://lupyuen.github.io/images/forgejo-mirror2.png)

1.  Enter the __GitHub URL__ of NuttX Repo

    Fill in the __Access Token__

    Uncheck __"This Repo Will Be A Mirror"__
    
    Check the following: __Migrate LFS Files__, __Wiki__, __Labels__, __Milestones__, __Releases__

    Set the __Repo Name__ to __`nuttx-update`__

    ![TODO](https://lupyuen.github.io/images/forgejo-update8.png)

1.  This will create a __Read-Write Mirror__...

    Forgejo __won't auto-sync__ our repo. But it will migrate the other items: Labels, Milestones, Releases (pic above)

    Don't select __Issues and Pull Requests__! Forgejo will hang forever, hitting errors. (Probably due to the sheer volume)

    TODO: Combine pics

    ![TODO](https://lupyuen.github.io/images/forgejo-update1.png)

    ![TODO](https://lupyuen.github.io/images/forgejo-update7.png)

1.  Assuming we didn't select Issues and Pull Requests...

    Forgejo creates our __Read-Write Mirror__

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-update9.png)

1.  How will we __sync the Read-Write Mirror__? By running this script...

    TODO: Sync script

# Appendix: Pull Request in Forgejo

_How different are Forgejo Pull Requests from GitHub?_

Let's find out!

1.  We create a Fork of our NuttX [__Read-Write Mirror__](TODO)

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-update4.png)

1.  Create a new branch: [__`test-branch`__](TODO). __Edit a file__ in our new branch.

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-update5.png)

1.  __Save the file__ to our new branch

    ![TODO](https://lupyuen.github.io/images/forgejo-update6.png)

1.  Click __"New Pull Request"__

    ![TODO](https://lupyuen.github.io/images/forgejo-pr1.png)

1.  Again click __"New Pull Request"__

    ![TODO](https://lupyuen.github.io/images/forgejo-pr2.png)

1.  Remember the __NuttX Template for Pull Requests__? It appears in Forgejo

    ![TODO](https://lupyuen.github.io/images/forgejo-pr3.png)

1.  Click __"Create Pull Request"__

    ![TODO](https://lupyuen.github.io/images/forgejo-pr4.png)

1.  And we'll see our __New Pull Request__

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-pr5.png)

1.  Indeed, no surprises! Everything works the same.

    ![TODO](https://lupyuen.github.io/images/forgejo-pr6.png)

1.  __Merging a Pull Request__ will trigger the exact same CI Workflow. Which won't run because we haven't configured the CI Servers.

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-actions1.png)

1.  Will Forgejo handle __Large Pull Requests__? Yep here's a Pull Request with 217 NuttX Commits

    [(Live Site)](TODO)

    ![TODO](https://lupyuen.github.io/images/forgejo-commits.png)

1.  Let's try not to __Merge any Pull Request__ into our Read-Write Mirror. We should keep it in sync with our Read-Only Mirror!

    TODO: Sync to GitHub

# Appendix: SSH Access in Forgejo

This section explains how we tested __SSH Access__ in our Forgejo Server.

Note: SSH Port for our Forgejo Server is __not exposed to the internet__ (for security reasons).

```bash
$ ssh-keygen -t ed25519 -a 100
## Save it to ~/.ssh/nuttx-forge
```

Edit __~/.ssh/config__ and add...

```text
Host nuttx-forge
  HostName localhost
  Port 222
  IdentityFile ~/.ssh/nuttx-forge
```

(__localhost__ will change to the External IP of our Forgejo Server)

In Forgejo Web:
- Click __Settings > SSH Keys__
- Paste the contents of __~/.ssh/nuttx-forge.pub__
- Click __Add Key__

![TODO](https://lupyuen.github.io/images/forgejo-ssh.png)

Finally we test the __SSH Access__...

```bash
$ ssh -T git@nuttx-forge  

Hi there, nuttx! You've successfully authenticated with the key named nuttx-forge (luppy@localhost), but Forgejo does not provide shell access.
If this is unexpected, please log in with password and setup Forgejo under another user.
```

We create a __Test Repo__ in our Forgejo Server...

![TODO](https://lupyuen.github.io/images/forgejo-ssh2.png)

And we __Commit over SSH__ to the Test Repo...

```bash
git clone git@nuttx-forge:nuttx/test.git
cd test
echo Testing >test.txt
git add .
git commit --all --message="Test Commit"
git push -u origin main
```

We should see the __Test Commit__. Yay!

![TODO](https://lupyuen.github.io/images/forgejo-ssh3.png)

# Appendix: SSH vs Docker Filesystem

_Why did we change the Docker Filesystem for Forgejo?_

Based on the [__Official Docs__](TODO): Forgejo should be configured to use a __Local Docker Filesystem__...

```yaml
services:
  server:
    volumes:
      - forgejo-data:/data
TODO
```

Let's try it on [__macOS Rancher Desktop__](TODO) and watch what happens...

```bash
## Connect to Forgejo Server over SSH
ssh -T -p 222 git@localhost
```

__Forgejo Server Log__ says...

```text
forgejo  | Authentication refused: bad ownership or modes for file /data/git/.ssh/authorized_keys
forgejo  | Connection closed by authenticating user git 172.22.0.1 port 47768 [preauth]
forgejo  | Authentication refused: bad ownership or modes for file /data/git/.ssh/authorized_keys
forgejo  | Connection closed by authenticating user git 172.22.0.1 port 40328 [preauth]
forgejo  | Authentication refused: bad ownership or modes for file /data/git/.ssh/authorized_keys
forgejo  | Connection closed by authenticating user git 172.22.0.1 port 39114 [preauth]
```

We check the __SSH Filesystem in macOS__...

```bash
$ ls -ld $HOME/nuttx-forgejo/forgejo/git/.ssh                
drwx------@ 4 luppy  staff  128 Dec 20 13:45 /Users/luppy/nuttx-forgejo/forgejo/git/.ssh

$ ls -l $HOME/nuttx-forgejo/forgejo/git/.ssh/authorized_keys 
-rw-------@ 1 luppy  staff  279 Dec 21 11:13 /Users/luppy/nuttx-forgejo/forgejo/git/.ssh/authorized_keys
```

Do the same __Inside Docker__...

```bash
$ sudo docker exec \
  -it \
  forgejo \
  /bin/bash

$ ls -ld /data/git/.ssh
drwx------    1 501      dialout        128 Dec 20 13:45 /data/git/.ssh
$ ls -l /data/git/.ssh/authorized_keys
-rw-------    1 501      dialout        279 Dec 21 11:13 /data/git/.ssh/authorized_keys
```

Aha! User ID should be __git__, not __501__! (Some kinda jeans?)

Too bad __chown__ won't work...

```bash
## Nope! Won't work in Rancher Desktop
exec su-exec root chown -R git /data/git/.ssh
```

(Rancher Desktop won't set permissions correctly for Local Filesystem) 

And that's why our [__docker-compose.yml__](TODO) points to __forgejo-data__ as the Data Volume (instead of Local Filesystem)

```yaml
services:
  server:
    volumes:
      - forgejo-data:/data
volumes:
  forgejo-data:
```
