# Auto-Rewind for Daily Test (Apache NuttX RTOS)

📝 _26 Feb 2025_

![TODO](https://lupyuen.github.io/images/rewind-title.jpg)

If the __Daily Test__ fails for [__Apache NuttX RTOS__](TODO)... Can we __Auto-Rewind__ and discover the __Breaking Commit__? Let's find out!

1.  Every Day at 00:00 UTC: [__Ubuntu Cron__](TODO) shall trigger a __Daily Buld and Test__ of NuttX for __QEMU RISC-V__ _(knsh64 / 64-bit Kernel Build)_

1.  __If The Test Fails:__ Our Machine will [__Backtrack The Commits__](TODO), rebuilding and retesting each commit _(on QEMU Emulator)_

1.  When it discovers the __Breaking Commit__: Our Machine shall post a [__Mastodon Alert__](TODO), that includes the _(suspicious)_ __Pull Request__

1.  __Bonus:__ The Machine will draft a [__Polite Note__](TODO) for our NuttX Colleague to investigate the Pull Request, please

_Why are we doing this?_

__If NuttX Fails on QEMU RISC-V:__ High chance that NuttX will also fail on __RISC-V SBCs__ like Ox64 BL808 and Oz64 SG2000.

Thus it's important to Nip the Bud and Fix the Bug, before it hurts our RISC-V Devs. _(Be Kind, Rewind!)_

# TODO

```text
Create Snippet
https://docs.gitlab.com/ee/api/snippets.html#create-new-snippet

snippet.json
<<
{
  "title": "This is a snippet",
  "description": "Hello World snippet",
  "visibility": "public",
  "files": [
    {
      "content": "Hello world",
      "file_path": "test.txt"
    }
  ]
}
>>

. $HOME/gitlab-token.sh
user=lupyuen
repo=nuttx-build-log
curl --url https://gitlab.com/api/v4/projects/$user%2F$repo/snippets \
  --header 'Content-Type: application/json' \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \

curl --request POST "https://gitlab.com/api/v4/projects/$user%2F$repo/snippets" \
  --header 'Content-Type: application/json' \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  -d @snippet.json

https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4800488
```

TODO

```text
Get Log

build_score{
target="rv-virt:knsh64_test5",
build_score_prev="1"
} == 0

Breaking Commit:
nuttx_hash="657247bda89d60112d79bb9b8d223eca5f9641b5"

build_score{
target="rv-virt:knsh64_test5",
nuttx_hash="657247bda89d60112d79bb9b8d223eca5f9641b5"
}

url="https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799962#L85"

Starting at Line 85: Search for lines starting with "+ " or "spawn"

wget https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799962/raw/main/ci-unknown.log
grep "^+ " ci-unknown.log

<<
+ /home/luppy/nuttx-build-farm/build-test-knsh64.sh 657247bda89d60112d79bb9b8d223eca5f9641b5 a6b9e718460a56722205c2a84a9b07b94ca664aa
+ nuttx_hash=657247bda89d60112d79bb9b8d223eca5f9641b5
+ apps_hash=a6b9e718460a56722205c2a84a9b07b94ca664aa
+ neofetch
+ tmp_path=/tmp/build-test-knsh64
+ rm -rf /tmp/build-test-knsh64
+ mkdir /tmp/build-test-knsh64
+ cd /tmp/build-test-knsh64
+ git clone https://github.com/apache/nuttx
+ git clone https://github.com/apache/nuttx-apps apps
+ [[ 657247bda89d60112d79bb9b8d223eca5f9641b5 != '' ]]
+ pushd nuttx
+ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
+ popd
+ [[ a6b9e718460a56722205c2a84a9b07b94ca664aa != '' ]]
+ pushd apps
+ git reset --hard a6b9e718460a56722205c2a84a9b07b94ca664aa
+ popd
+ set +x
+ riscv-none-elf-gcc -v
+ rustup --version
+ rustc --version
+ cd nuttx
+ tools/configure.sh rv-virt:knsh64
+ make -j
+ riscv-none-elf-size nuttx
+ make -j export
+ ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-12.8.0.tar.gz
+ make -j import
+ popd
+ qemu-system-riscv64 --version
+ script=qemu-riscv-knsh64
+ wget https://raw.githubusercontent.com/lupyuen/nuttx-riscv64/main/qemu-riscv-knsh64.exp
spawn qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic
+ expect ./qemu-riscv-knsh64.exp
>>

Include Commit Info
<<
+ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
HEAD is now at 657247bda8 libc/modlib: preprocess gnu-elf.ld
NuttX Source: https://github.com/apache/nuttx/tree/657247bda89d60112d79bb9b8d223eca5f9641b5
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa
>>

Include QEMU and OpenSBI version
<<
+ qemu-system-riscv64 --version
QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.4)

+ expect ./qemu-riscv-knsh64.exp
spawn qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic

OpenSBI v1.3
>>

Extract Log from Line Number till "===== "
Extract 5 lines:
"+ git reset "
"NuttX Source: "
"NuttX Apps: "
"+ qemu"
"+ expect ./qemu"

Search for lines starting with "===== Error: Test Failed" or "===== Test OK"
Backtrack last 10 lines

```

TODO

```text
Get Breaking PR

List pull requests associated with a commit
https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28#list-pull-requests-associated-with-a-commit

commit=be40c01ddd6f43a527abeae31042ba7978aabb58
curl -L \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/apache/nuttx/commits/$commit/pulls

[
  {
    "url": "https://api.github.com/repos/apache/nuttx/pulls/15444",
    "id": 2263146908,
    "node_id": "PR_kwDODZiUac6G5OGc",
    "html_url": "https://github.com/apache/nuttx/pull/15444",
    "diff_url": "https://github.com/apache/nuttx/pull/15444.diff",
    "patch_url": "https://github.com/apache/nuttx/pull/15444.patch",
    "issue_url": "https://api.github.com/repos/apache/nuttx/issues/15444",
    "number": 15444,
    "state": "closed",
    "locked": false,
    "title": "modlib: preprocess gnu-elf.ld for executable ELF",
    "user": {
      "login": "yf13",
      "id": 5899566,
      "node_id": "MDQ6VXNlcjU4OTk1NjY=",
      "avatar_url": "https://avatars.githubusercontent.com/u/5899566?v=4",
      "gravatar_id": "",
      "url": "https://api.github.com/users/yf13",
      "html_url": "https://github.com/yf13",
      "followers_url": "https://api.github.com/users/yf13/followers",
      "following_url": "https://api.github.com/users/yf13/following{/other_user}",
      "gists_url": "https://api.github.com/users/yf13/gists{/gist_id}",
      "starred_url": "https://api.github.com/users/yf13/starred{/owner}{/repo}",
      "subscriptions_url": "https://api.github.com/users/yf13/subscriptions",
      "organizations_url": "https://api.github.com/users/yf13/orgs",
      "repos_url": "https://api.github.com/users/yf13/repos",
      "events_url": "https://api.github.com/users/yf13/events{/privacy}",
      "received_events_url": "https://api.github.com/users/yf13/received_events",
      "type": "User",
      "user_view_type": "public",
      "site_admin": false
    },
    "body": "# Summary\r\n\r\nThis allows apps for kernel mode NuttX (e.g. on arm/qemu-armv7a) can be built as executable type ELF files. Benefits of executable programs are smaller in size and easier GDB debugging.\r\n\r\nInitial scope was only for qemu-armv7a but it used an almost duplicated `gnu-elf.ld` which differs only at `.text` and `.data` addresses from the `gnu-elf.ld` in modlib.  \r\n\r\nTo avoid such duplications, a preprocessed `gnu-elf.ld` in modlib is added  so that to adapt to target config. This requires minor tweaks for `addrenv.h` so that some macros can be included in `gnu-elf.ld.in`.\r\n\r\n# Impacts\r\n\r\nHardware: qemu-armv7a or using kernel build.\r\n\r\n# Testing\r\n\r\n- local checks with QEMU v6.2 on Ubuntu 22.04: `qemu-armv7a:knsh`, `bl602evb:elf`.\r\n- CI checks\r\n\r\n",
    "created_at": "2025-01-07T06:30:43Z",
    "updated_at": "2025-01-14T04:41:41Z",
    "closed_at": "2025-01-11T10:54:36Z",
    "merged_at": "2025-01-11T10:54:36Z",
    "merge_commit_sha": "ff488133c9348901fc6abd3890299a9f9d81dec6",
    "assignee": null,
    "assignees": [

    ],
    "requested_reviewers": [

    ],
    "requested_teams": [

    ],
    "labels": [
      {
        "id": 7292036618,
        "node_id": "LA_kwDODZiUac8AAAABsqOmCg",
        "url": "https://api.github.com/repos/apache/nuttx/labels/Arch:%20all",
        "name": "Arch: all",
        "color": "DC5544",
        "default": false,
        "description": "Issues that apply to all architectures"
      },
      {
        "id": 7292038640,
        "node_id": "LA_kwDODZiUac8AAAABsqOt8A",
        "url": "https://api.github.com/repos/apache/nuttx/labels/Arch:%20arm",
        "name": "Arch: arm",
        "color": "DC5544",
        "default": false,
        "description": "Issues related to ARM (32-bit) architecture"
      },
      {
        "id": 7292097170,
        "node_id": "LA_kwDODZiUac8AAAABsqSSkg",
        "url": "https://api.github.com/repos/apache/nuttx/labels/Area:%20OS%20Components",
        "name": "Area: OS Components",
        "color": "0075ca",
        "default": false,
        "description": "OS Components issues"
      },
      {
        "id": 7486822345,
        "node_id": "LA_kwDODZiUac8AAAABvj_XyQ",
        "url": "https://api.github.com/repos/apache/nuttx/labels/Size:%20S",
        "name": "Size: S",
        "color": "FEF2C0",
        "default": false,
        "description": "The size of the change in this PR is small"
      }
    ],
    "milestone": null,
    "draft": false,
    "commits_url": "https://api.github.com/repos/apache/nuttx/pulls/15444/commits",
    "review_comments_url": "https://api.github.com/repos/apache/nuttx/pulls/15444/comments",
    "review_comment_url": "https://api.github.com/repos/apache/nuttx/pulls/comments{/number}",
    "comments_url": "https://api.github.com/repos/apache/nuttx/issues/15444/comments",
    "statuses_url": "https://api.github.com/repos/apache/nuttx/statuses/1be695191cd77b426ac53914cf0ebc0e60617c8c",
    "head": {
      "label": "yf13:a7mi",
      "ref": "a7mi",
      "sha": "1be695191cd77b426ac53914cf0ebc0e60617c8c",
      "user": {
        "login": "yf13",
        "id": 5899566,
        "node_id": "MDQ6VXNlcjU4OTk1NjY=",
        "avatar_url": "https://avatars.githubusercontent.com/u/5899566?v=4",
        "gravatar_id": "",
        "url": "https://api.github.com/users/yf13",
        "html_url": "https://github.com/yf13",
        "followers_url": "https://api.github.com/users/yf13/followers",
        "following_url": "https://api.github.com/users/yf13/following{/other_user}",
        "gists_url": "https://api.github.com/users/yf13/gists{/gist_id}",
        "starred_url": "https://api.github.com/users/yf13/starred{/owner}{/repo}",
        "subscriptions_url": "https://api.github.com/users/yf13/subscriptions",
        "organizations_url": "https://api.github.com/users/yf13/orgs",
        "repos_url": "https://api.github.com/users/yf13/repos",
        "events_url": "https://api.github.com/users/yf13/events{/privacy}",
        "received_events_url": "https://api.github.com/users/yf13/received_events",
        "type": "User",
        "user_view_type": "public",
        "site_admin": false
      },
      "repo": {
        "id": 730975045,
        "node_id": "R_kgDOK5HLRQ",
        "name": "nuttx",
        "full_name": "yf13/nuttx",
        "private": false,
        "owner": {
          "login": "yf13",
          "id": 5899566,
          "node_id": "MDQ6VXNlcjU4OTk1NjY=",
          "avatar_url": "https://avatars.githubusercontent.com/u/5899566?v=4",
          "gravatar_id": "",
          "url": "https://api.github.com/users/yf13",
          "html_url": "https://github.com/yf13",
          "followers_url": "https://api.github.com/users/yf13/followers",
          "following_url": "https://api.github.com/users/yf13/following{/other_user}",
          "gists_url": "https://api.github.com/users/yf13/gists{/gist_id}",
          "starred_url": "https://api.github.com/users/yf13/starred{/owner}{/repo}",
          "subscriptions_url": "https://api.github.com/users/yf13/subscriptions",
          "organizations_url": "https://api.github.com/users/yf13/orgs",
          "repos_url": "https://api.github.com/users/yf13/repos",
          "events_url": "https://api.github.com/users/yf13/events{/privacy}",
          "received_events_url": "https://api.github.com/users/yf13/received_events",
          "type": "User",
          "user_view_type": "public",
          "site_admin": false
        },
        "html_url": "https://github.com/yf13/nuttx",
        "description": "Apache NuttX is a mature, real-time embedded operating system (RTOS)",
        "fork": true,
        "url": "https://api.github.com/repos/yf13/nuttx",
        "forks_url": "https://api.github.com/repos/yf13/nuttx/forks",
        "keys_url": "https://api.github.com/repos/yf13/nuttx/keys{/key_id}",
        "collaborators_url": "https://api.github.com/repos/yf13/nuttx/collaborators{/collaborator}",
        "teams_url": "https://api.github.com/repos/yf13/nuttx/teams",
        "hooks_url": "https://api.github.com/repos/yf13/nuttx/hooks",
        "issue_events_url": "https://api.github.com/repos/yf13/nuttx/issues/events{/number}",
        "events_url": "https://api.github.com/repos/yf13/nuttx/events",
        "assignees_url": "https://api.github.com/repos/yf13/nuttx/assignees{/user}",
        "branches_url": "https://api.github.com/repos/yf13/nuttx/branches{/branch}",
        "tags_url": "https://api.github.com/repos/yf13/nuttx/tags",
        "blobs_url": "https://api.github.com/repos/yf13/nuttx/git/blobs{/sha}",
        "git_tags_url": "https://api.github.com/repos/yf13/nuttx/git/tags{/sha}",
        "git_refs_url": "https://api.github.com/repos/yf13/nuttx/git/refs{/sha}",
        "trees_url": "https://api.github.com/repos/yf13/nuttx/git/trees{/sha}",
        "statuses_url": "https://api.github.com/repos/yf13/nuttx/statuses/{sha}",
        "languages_url": "https://api.github.com/repos/yf13/nuttx/languages",
        "stargazers_url": "https://api.github.com/repos/yf13/nuttx/stargazers",
        "contributors_url": "https://api.github.com/repos/yf13/nuttx/contributors",
        "subscribers_url": "https://api.github.com/repos/yf13/nuttx/subscribers",
        "subscription_url": "https://api.github.com/repos/yf13/nuttx/subscription",
        "commits_url": "https://api.github.com/repos/yf13/nuttx/commits{/sha}",
        "git_commits_url": "https://api.github.com/repos/yf13/nuttx/git/commits{/sha}",
        "comments_url": "https://api.github.com/repos/yf13/nuttx/comments{/number}",
        "issue_comment_url": "https://api.github.com/repos/yf13/nuttx/issues/comments{/number}",
        "contents_url": "https://api.github.com/repos/yf13/nuttx/contents/{+path}",
        "compare_url": "https://api.github.com/repos/yf13/nuttx/compare/{base}...{head}",
        "merges_url": "https://api.github.com/repos/yf13/nuttx/merges",
        "archive_url": "https://api.github.com/repos/yf13/nuttx/{archive_format}{/ref}",
        "downloads_url": "https://api.github.com/repos/yf13/nuttx/downloads",
        "issues_url": "https://api.github.com/repos/yf13/nuttx/issues{/number}",
        "pulls_url": "https://api.github.com/repos/yf13/nuttx/pulls{/number}",
        "milestones_url": "https://api.github.com/repos/yf13/nuttx/milestones{/number}",
        "notifications_url": "https://api.github.com/repos/yf13/nuttx/notifications{?since,all,participating}",
        "labels_url": "https://api.github.com/repos/yf13/nuttx/labels{/name}",
        "releases_url": "https://api.github.com/repos/yf13/nuttx/releases{/id}",
        "deployments_url": "https://api.github.com/repos/yf13/nuttx/deployments",
        "created_at": "2023-12-13T04:50:13Z",
        "updated_at": "2025-01-22T05:52:32Z",
        "pushed_at": "2025-01-27T01:39:23Z",
        "git_url": "git://github.com/yf13/nuttx.git",
        "ssh_url": "git@github.com:yf13/nuttx.git",
        "clone_url": "https://github.com/yf13/nuttx.git",
        "svn_url": "https://github.com/yf13/nuttx",
        "homepage": "https://nuttx.apache.org/",
        "size": 315415,
        "stargazers_count": 2,
        "watchers_count": 2,
        "language": "C",
        "has_issues": false,
        "has_projects": true,
        "has_downloads": true,
        "has_wiki": false,
        "has_pages": true,
        "has_discussions": false,
        "forks_count": 0,
        "mirror_url": null,
        "archived": false,
        "disabled": false,
        "open_issues_count": 0,
        "license": {
          "key": "apache-2.0",
          "name": "Apache License 2.0",
          "spdx_id": "Apache-2.0",
          "url": "https://api.github.com/licenses/apache-2.0",
          "node_id": "MDc6TGljZW5zZTI="
        },
        "allow_forking": true,
        "is_template": false,
        "web_commit_signoff_required": false,
        "topics": [

        ],
        "visibility": "public",
        "forks": 0,
        "open_issues": 0,
        "watchers": 2,
        "default_branch": "master"
      }
    },
    "base": {
      "label": "apache:master",
      "ref": "master",
      "sha": "91c71ed00a61ca4ba46000be9e814074e6a70e49",
      "user": {
        "login": "apache",
        "id": 47359,
        "node_id": "MDEyOk9yZ2FuaXphdGlvbjQ3MzU5",
        "avatar_url": "https://avatars.githubusercontent.com/u/47359?v=4",
        "gravatar_id": "",
        "url": "https://api.github.com/users/apache",
        "html_url": "https://github.com/apache",
        "followers_url": "https://api.github.com/users/apache/followers",
        "following_url": "https://api.github.com/users/apache/following{/other_user}",
        "gists_url": "https://api.github.com/users/apache/gists{/gist_id}",
        "starred_url": "https://api.github.com/users/apache/starred{/owner}{/repo}",
        "subscriptions_url": "https://api.github.com/users/apache/subscriptions",
        "organizations_url": "https://api.github.com/users/apache/orgs",
        "repos_url": "https://api.github.com/users/apache/repos",
        "events_url": "https://api.github.com/users/apache/events{/privacy}",
        "received_events_url": "https://api.github.com/users/apache/received_events",
        "type": "Organization",
        "user_view_type": "public",
        "site_admin": false
      },
      "repo": {
        "id": 228103273,
        "node_id": "MDEwOlJlcG9zaXRvcnkyMjgxMDMyNzM=",
        "name": "nuttx",
        "full_name": "apache/nuttx",
        "private": false,
        "owner": {
          "login": "apache",
          "id": 47359,
          "node_id": "MDEyOk9yZ2FuaXphdGlvbjQ3MzU5",
          "avatar_url": "https://avatars.githubusercontent.com/u/47359?v=4",
          "gravatar_id": "",
          "url": "https://api.github.com/users/apache",
          "html_url": "https://github.com/apache",
          "followers_url": "https://api.github.com/users/apache/followers",
          "following_url": "https://api.github.com/users/apache/following{/other_user}",
          "gists_url": "https://api.github.com/users/apache/gists{/gist_id}",
          "starred_url": "https://api.github.com/users/apache/starred{/owner}{/repo}",
          "subscriptions_url": "https://api.github.com/users/apache/subscriptions",
          "organizations_url": "https://api.github.com/users/apache/orgs",
          "repos_url": "https://api.github.com/users/apache/repos",
          "events_url": "https://api.github.com/users/apache/events{/privacy}",
          "received_events_url": "https://api.github.com/users/apache/received_events",
          "type": "Organization",
          "user_view_type": "public",
          "site_admin": false
        },
        "html_url": "https://github.com/apache/nuttx",
        "description": "Apache NuttX is a mature, real-time embedded operating system (RTOS)",
        "fork": false,
        "url": "https://api.github.com/repos/apache/nuttx",
        "forks_url": "https://api.github.com/repos/apache/nuttx/forks",
        "keys_url": "https://api.github.com/repos/apache/nuttx/keys{/key_id}",
        "collaborators_url": "https://api.github.com/repos/apache/nuttx/collaborators{/collaborator}",
        "teams_url": "https://api.github.com/repos/apache/nuttx/teams",
        "hooks_url": "https://api.github.com/repos/apache/nuttx/hooks",
        "issue_events_url": "https://api.github.com/repos/apache/nuttx/issues/events{/number}",
        "events_url": "https://api.github.com/repos/apache/nuttx/events",
        "assignees_url": "https://api.github.com/repos/apache/nuttx/assignees{/user}",
        "branches_url": "https://api.github.com/repos/apache/nuttx/branches{/branch}",
        "tags_url": "https://api.github.com/repos/apache/nuttx/tags",
        "blobs_url": "https://api.github.com/repos/apache/nuttx/git/blobs{/sha}",
        "git_tags_url": "https://api.github.com/repos/apache/nuttx/git/tags{/sha}",
        "git_refs_url": "https://api.github.com/repos/apache/nuttx/git/refs{/sha}",
        "trees_url": "https://api.github.com/repos/apache/nuttx/git/trees{/sha}",
        "statuses_url": "https://api.github.com/repos/apache/nuttx/statuses/{sha}",
        "languages_url": "https://api.github.com/repos/apache/nuttx/languages",
        "stargazers_url": "https://api.github.com/repos/apache/nuttx/stargazers",
        "contributors_url": "https://api.github.com/repos/apache/nuttx/contributors",
        "subscribers_url": "https://api.github.com/repos/apache/nuttx/subscribers",
        "subscription_url": "https://api.github.com/repos/apache/nuttx/subscription",
        "commits_url": "https://api.github.com/repos/apache/nuttx/commits{/sha}",
        "git_commits_url": "https://api.github.com/repos/apache/nuttx/git/commits{/sha}",
        "comments_url": "https://api.github.com/repos/apache/nuttx/comments{/number}",
        "issue_comment_url": "https://api.github.com/repos/apache/nuttx/issues/comments{/number}",
        "contents_url": "https://api.github.com/repos/apache/nuttx/contents/{+path}",
        "compare_url": "https://api.github.com/repos/apache/nuttx/compare/{base}...{head}",
        "merges_url": "https://api.github.com/repos/apache/nuttx/merges",
        "archive_url": "https://api.github.com/repos/apache/nuttx/{archive_format}{/ref}",
        "downloads_url": "https://api.github.com/repos/apache/nuttx/downloads",
        "issues_url": "https://api.github.com/repos/apache/nuttx/issues{/number}",
        "pulls_url": "https://api.github.com/repos/apache/nuttx/pulls{/number}",
        "milestones_url": "https://api.github.com/repos/apache/nuttx/milestones{/number}",
        "notifications_url": "https://api.github.com/repos/apache/nuttx/notifications{?since,all,participating}",
        "labels_url": "https://api.github.com/repos/apache/nuttx/labels{/name}",
        "releases_url": "https://api.github.com/repos/apache/nuttx/releases{/id}",
        "deployments_url": "https://api.github.com/repos/apache/nuttx/deployments",
        "created_at": "2019-12-14T23:27:55Z",
        "updated_at": "2025-01-29T04:43:44Z",
        "pushed_at": "2025-01-29T04:43:39Z",
        "git_url": "git://github.com/apache/nuttx.git",
        "ssh_url": "git@github.com:apache/nuttx.git",
        "clone_url": "https://github.com/apache/nuttx.git",
        "svn_url": "https://github.com/apache/nuttx",
        "homepage": "https://nuttx.apache.org/",
        "size": 316389,
        "stargazers_count": 3066,
        "watchers_count": 3066,
        "language": "C",
        "has_issues": true,
        "has_projects": true,
        "has_downloads": true,
        "has_wiki": false,
        "has_pages": false,
        "has_discussions": false,
        "forks_count": 1232,
        "mirror_url": null,
        "archived": false,
        "disabled": false,
        "open_issues_count": 572,
        "license": {
          "key": "apache-2.0",
          "name": "Apache License 2.0",
          "spdx_id": "Apache-2.0",
          "url": "https://api.github.com/licenses/apache-2.0",
          "node_id": "MDc6TGljZW5zZTI="
        },
        "allow_forking": true,
        "is_template": false,
        "web_commit_signoff_required": false,
        "topics": [
          "embedded",
          "mcu",
          "microcontroller",
          "nuttx",
          "real-time",
          "rtos"
        ],
        "visibility": "public",
        "forks": 1232,
        "open_issues": 572,
        "watchers": 3066,
        "default_branch": "master"
      }
    },
    "_links": {
      "self": {
        "href": "https://api.github.com/repos/apache/nuttx/pulls/15444"
      },
      "html": {
        "href": "https://github.com/apache/nuttx/pull/15444"
      },
      "issue": {
        "href": "https://api.github.com/repos/apache/nuttx/issues/15444"
      },
      "comments": {
        "href": "https://api.github.com/repos/apache/nuttx/issues/15444/comments"
      },
      "review_comments": {
        "href": "https://api.github.com/repos/apache/nuttx/pulls/15444/comments"
      },
      "review_comment": {
        "href": "https://api.github.com/repos/apache/nuttx/pulls/comments{/number}"
      },
      "commits": {
        "href": "https://api.github.com/repos/apache/nuttx/pulls/15444/commits"
      },
      "statuses": {
        "href": "https://api.github.com/repos/apache/nuttx/statuses/1be695191cd77b426ac53914cf0ebc0e60617c8c"
      }
    },
    "author_association": "CONTRIBUTOR",
    "auto_merge": null,
    "active_lock_reason": null
  }
]
```

TODO

```text
Get Breaking Commit

build_score{
target="rv-virt:knsh64_test5",
build_score_prev="1"
} == 0

Get nuttx_hash_prev
"be40c01ddd6f43a527abeae31042ba7978aabb58"

build_score{apps_hash="a6b9e718460a56722205c2a84a9b07b94ca664aa", apps_hash_next="a6b9e718460a56722205c2a84a9b07b94ca664aa", apps_hash_prev="a6b9e718460a56722205c2a84a9b07b94ca664aa", arch="unknown", board="rv-virt", build_score_next="0", build_score_prev="1", config="knsh64_test5", exported_instance="rv-virt:knsh64_test5@657247bda89d60112d79bb9b8d223eca5f9641b5@a6b9e718460a56722205c2a84a9b07b94ca664aa", exported_job="rewind", group="unknown", instance="localhost:9091", job="pushgateway", msg="+ /home/luppy/nuttx-build-farm/build-test-knsh64.sh 48846954d8506e1c95089a8654787fdc42cc098c a6b9e718460a56722205c2a84a9b07b94ca664aa Now running https://github.com/lupyuen/nuttx-build-farm/blob/main/build-test-knsh64.sh 48846954d8506e1c95089a8654787fdc42cc098c a6b9e718460a56722205c2a84a9b07b94ca664aa + nuttx_hash=48846954d8506e1c95089a8654787fdc42cc098c + apps_hash=a6b9e718460a56722205c2a84a9b07b94ca664aa + neofetch .-/+oossssoo+/-. `:+ssssssssssssssssss+:` -+ssssssssssssssssssyyssss+-", nuttx_hash="657247bda89d60112d79bb9b8d223eca5f9641b5", nuttx_hash_next="48846954d8506e1c95089a8654787fdc42cc098c", nuttx_hash_prev="be40c01ddd6f43a527abeae31042ba7978aabb58", subarch="unknown", target="rv-virt:knsh64_test5", timestamp="2025-01-11T10:54:36", timestamp_log="2025-01-29T04:59:10.699Z", url="https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799962#L1629", url_display="gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799962#L1629", user="rewind", version="3"}
```

TODO

```text
nuttx_hash_next
nuttx_hash_prev

apps_hash_next
apps_prev_next

build_score_next
build_score_prev

if group == "unknown"
Search for
"build / test failed" vs "build / test ok"
"this commit" vs "previous commit" vs "next commit"

extract nuttx hash
extract apps hash

if failed: build_score=0
if successful: build_score=1
```

TODO

```text
Query prometheus for today's builds by rewind
Sort by timestamp_log

Search for
***** BUILD / TEST FAILED FOR THIS COMMIT: nuttx @ 657247bda89d60112d79bb9b8d223eca5f9641b5 / nuttx-apps @ a6b9e718460a56722205c2a84a9b07b94ca664aa
***** Build / Test OK for Previous Commit: nuttx @ be40c01ddd6f43a527abeae31042ba7978aabb58 / nuttx-apps @ a6b9e718460a56722205c2a84a9b07b94ca664aa
***** BUILD / TEST FAILED FOR NEXT COMMIT: nuttx @ 48846954d8506e1c95089a8654787fdc42cc098c / nuttx-apps @ a6b9e718460a56722205c2a84a9b07b94ca664aa
https://gitlab.com/lupyuen/nuttx-build-log/-/snippets/4799243#L1629

https://github.com/XAMPPRocky/octocrab/blob/ce8c885dc2701c891ce868c846fa25d32fd44ba2/src/api/commits/associated_pull_requests.rs#L75
    #[tokio::test]
    async fn associated_pull_requests_serializes_correctly() {
        use super::PullRequestTarget;

        let octocrab = crate::Octocrab::default();
        let handler = octocrab.commits("owner", "repo");
        let associated_prs =
            handler.associated_pull_requests(PullRequestTarget::Sha("commit_sha".to_string()));

        assert_eq!(
            serde_json::to_value(associated_prs).unwrap(),
            serde_json::json!({
                "target": "commit_sha"
            })
        );
    }

Sort by Log Timestamp

Add Log Timestamp
https://github.com/lupyuen/ingest-nuttx-builds/commit/055149d999c6727183b843feedce6d3086062a24

Sort: Timestamp + NuttX Hash
TODO: Add timestamp_log (from Snippet)

Parse OSTest correctly
https://github.com/lupyuen/ingest-nuttx-builds/commit/b4eb156075002bafa510230c2120f70e09f7cf12

. ../gitlab-token.sh && glab auth status && ./rewind-build.sh rv-virt:knsh64_test aa0aecbd80a2ce69ee33ced41b7677f8521acd43 a6b9e718460a56722205c2a84a9b07b94ca664aa

30 mins for 7 rewinds

build-test
If fail
Rewind-build
Use latest hashes

lookup prometheus
Compose Mastodon message 
Get pr, author 
Link to build history 
Earlier build is ok
Run log snippet 
Uname
Last few lines

TODO: daily cron
https://help.ubuntu.com/community/CronHowto

TODO: Get hashes from Prometheus 

https://github.com/lupyuen/nuttx-riscv64/releases/tag/qemu-riscv-knsh64-2025-01-12
NuttX Source: https://github.com/apache/nuttx/tree/aa0aecbd80a2ce69ee33ced41b7677f8521acd43
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa

https://github.com/apache/nuttx/pull/15444#issuecomment-2585595498
Sorry @yf13: This PR is causing "Instruction page fault" for rv-virt:knsh64. Wonder if there's something I missed in my testing steps? Thanks!

https://gist.github.com/lupyuen/60d54514ce9a8589b56ed6207c356d95#file-special-qemu-riscv-knsh64-log-L1396
+ git reset --hard 657247bda89d60112d79bb9b8d223eca5f9641b5
HEAD is now at 657247bda8 libc/modlib: preprocess gnu-elf.ld
NuttX Source: https://github.com/apache/nuttx/tree/657247bda89d60112d79bb9b8d223eca5f9641b5
NuttX Apps: https://github.com/apache/nuttx-apps/tree/a6b9e718460a56722205c2a84a9b07b94ca664aa
+ tools/configure.sh rv-virt:knsh64
+ make -j
+ make export
+ pushd ../apps
+ ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-12.8.0.tar.gz
+ make import
+ popd
+ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -kernel nuttx -nographic
QEMU emulator version 9.2.0
OpenSBI v1.5.1
ABC
riscv_exception: EXCEPTION: Instruction page fault. MCAUSE: 000000000000000c, EPC: 000000018000001a, MTVAL: 000000018000001a
riscv_exception: Segmentation fault in PID 2: /system/bin/init
(Earlier Commit is OK)
```

# What's Next

TODO

Many Thanks to the awesome __NuttX Admins__ and __NuttX Devs__! And [__My Sponsors__](https://lupyuen.org/articles/sponsor), for sticking with me all these years.

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__My Other Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Older Project: "NuttX for Star64 JH7110"__](https://nuttx-forge.org/lupyuen/nuttx-star64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/rewind.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/rewind.md)
