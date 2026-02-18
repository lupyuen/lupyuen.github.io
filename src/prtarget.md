# GitHub Actions pull_request_target vs Apache NuttX RTOS

📝 _1 Mar 2026_

![TODO](https://lupyuen.org/images/prtarget-title.jpg)

In GitHub Actions: This is the typical way that we [__Label a Pull Request__](https://github.com/actions/labeler?tab=readme-ov-file#create-workflow). But it's _potentially dangerous_, guess why: [.github/workflows/labeler.yml](https://github.com/apache/nuttx/blob/cf30528231a23c7329198bba220e8fcbac98baa2/.github/workflows/labeler.yml)

```yaml
## When a Pull Request is submitted...
on:
  - pull_request_target
jobs:
  labeler: ...
    steps:
      ## Checkout the repo
      - uses: actions/checkout@v6

      ## Assign the PR Labels based on the updated Paths
      - uses: actions/labeler@main
        with:
          repo-token:  "${{ secrets.GITHUB_TOKEN }}"

      ## Assign the PR Labels based on the PR Size
      - uses: codelytv/pr-size-labeler@v1.10.3
        with:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

TODO

# TODO

_How did we discover this problem?_

We were notified about the [__Unsafe pull_request_target__](https://github.com/apache/nuttx/issues/18359) during a Security Scan...

> "pull_request_target was found as a workflow trigger ... If after after 60 days these problems are not addressed, we will turn off builds"

TODO

# TODO

Hi Infra Team: We have removed the pull_request_target trigger. Here is the completed Pull Request:

https://github.com/apache/nuttx/pull/18404

pr-size-labeler/src/github.sh at main · CodelyTV/pr-size-labeler

https://github.com/CodelyTV/pr-size-labeler/blob/main/src/github.sh

labeler/src/changedFiles.ts at main · actions/labeler

https://github.com/actions/labeler/blob/main/src/changedFiles.ts


Wow: Apache NuttX Project dies in 60 days... Unless we rip out pull_request_target from GitHub Actions!

Asf infra policy says...

We're embedded devs, not CI Security Experts 
Thus begins our dive deep into the rabbit hole of pull_request_target. And why did GitHub create the hole in the first place?

But technically we don't export the token right?

(1) We have a nagging worry that pr-size-labeler might (someday) do scary things with the GitHub Token? How do we prove to ASF Infra that pr-size-labeler is 100% safe?

(2) pull_request_target feels generally unsafe. Let's nip this bug in the bud, before someone does something dangerous. (Explained below)

(3) We only have 60 days to pull out pull_request_target. We're all part-time Embedded Devs, not full-time Security Experts. After Fixing: Don't forget the 24 x 7 Continuous Monitoring! Let's all do now, talk later?

Why did we do it in the first place?

Denial, Maybe? Why would ASF stop us from using pull_request_target, if everyone was using? But now we realise it's really unsafe, especially for non-security experts

Why isn't workflow_run in the ASF Security Policy?

Checkout then labeler
extremely dangerous
npm install
since we are embedded devs, not CI Security Experts

Very common to see checkout then labeler
"actions/labeler@v6" language:YAMLCode search results https://share.google/nhD8pxP82ZzhzeNBt

Why?
Maybe suggested here: https://github.com/actions/labeler?tab=readme-ov-file#using-configuration-path-input-together-with-the-actionscheckout-action
Checkout the config file
Why not checkout one single file like this

TODO: Why use labeler?
selective build

Pros and Cons of the new implementation?

(1) New Implementation is Safer: We don't use pull_request_target, and we don't checkout the Entire NuttX Repo based on the PR. So we'll never execute any Malicious Code submitted in the PR.
(2) New Implementation is Quicker: It's faster since we don't checkout the entire repo. Also pr-size-labeler actually runs in a Docker Container, we don't need that any more.
(3) But it might be quirky under Heavy Load. Remember that workflow_run trigger will write the PR Labels as a Second Job? When we run out of GitHub Runners, the PR Labels might never be applied. The Build Logic in arch.yml will execute a Complete NuttX Build if it can't find the PR Labels.
(4) Will the Build Workflow be triggered too early, before the workflow_run trigger? Hopefully not. The Build Workflow begins in the Fetch-Source stage, checking out the Entire Repo and uploading everything in 1.5 minutes, followed by the Select-Builds stage (arch.yml) reading the PR Labels. Before 1.5 minutes, rightfully our workflow_run trigger would have written the PR Labels to the PR.

Are we reimplementing EVERYTHING from the Official GitHub Labeler actions/labeler?

We won't implement the Entire GitHub Labeler actions/labeler, just the bare minimum needed for NuttX. We're emulating the Labeler Config .github/labeler.yml as is, because someday GitHub might invent a Secure Way to Label PRs inside pull_request_trigger. (Then we'll switch back to the Official GitHub Labeler actions/labeler)
There's something really jinxed about the way GitHub designed PR Labeling in pull_request_trigger, it's a terrible security hack. I'll write an article about this someday :-)

Based on Actual Logs: New PR Labeling completes in 16 elapsed seconds, spanning 2 jobs. Previously: 24 elapsed seconds, in 1 job.

# Action List

Thanks @simbit18! Yep eventually we need some GitHub Script (JavaScript), here's my plan...

(1) `[Done]` Verify that PRs can be Labeled using the Two-Step Solution: pull_request trigger + workflow_run trigger [(explained here)](https://github.com/apache/nuttx/issues/18359#issuecomment-3869143242).

(2) `[Done]` But the Two-Step Solution won't work with `pr-size-labeler` and `actions/labeler`. These actions will work only with pull_request_target

(3) `[Done]` Which means we need our own GitHub Script (JavaScript) for doing the Size Labeling (S / M / L) and Arch Labeling (e.g. `arch: risc-v`)

(3a) `[Done]` How do we fetch the added / deleted / modified lines from the PR? We'll call GitHub Script (JavaScript) [`pulls.listFiles.endpoint.merge`](https://github.com/actions/labeler/blob/main/src/changedFiles.ts#L25-L46)

(4) `[Done]` Arch Labeling (e.g. `arch: risc-v`) looks straightforward. We just read the rules from [.github/labeler.yml](https://github.com/apache/nuttx/blob/master/.github/labeler.yml) and apply them.

(5) `[Done]` Size Labeling (S / M / L) is more tricky. I suggest we hardcode with `size: unknown` until we find a CLI Tool that can count Lines of Code  accurately.

(5a) `[TODO]` But I'll explore the PR Size Label anyway. It might be easy, because GitHub API already counts the changed lines for us.

(6) That's assuming that the Size Label isn't actually consumed by any of our GitHub Workflows today? I used it for the LLM Bot for PR Review, but I stopped the bot because Gemini upgraded their API and it broke our bot.

(7) Reading all the security docs, I'm pretty convinced that pull_request_target is "evil". Even if we can get an exemption from ASF Infra, someday someone can easily introduce a security hole, because pull_request_target needs to be maintained by a Security Expert.

(8) `[Done]` Thus I would rather write our own simple GitHub Script (JavaScript) + pull_request trigger + workflow_run trigger to do the labeling. And avoid all these potential security holes. 

(9) `[Done]` Remember to run [zizmor](https://woodruffw.github.io/zizmor/) periodically to check for security issues in GitHub Actions

(10) `[TODO]` Work out all the Test Cases for our new implementation of PR Labeling:
- Simple PR: Arm32-only, Arm64-only, RISC-V-only, ...
- Complex PR: Drivers, Arm32 + Arm64, Arm32 + RISC-V, ...
- Doc PR, ...

(11) `[TODO]` I'll hang out on Slack and find out how other Apache Projects are handling pull_request_target

60 days ago we received a notification 
60 days to Miri Marathon!
Can we save the NuttX Project in 60 days?

24x7 standby 
Except for Marathon Training (7 hours / 42 km)

Appendix: Test Cases


# TODO

[.github/workflows/labeler.yml](https://github.com/apache/nuttx/blob/cf30528231a23c7329198bba220e8fcbac98baa2/.github/workflows/labeler.yml)

```yaml
name: "Pull Request Labeler"
on:
  - pull_request_target

jobs:
  labeler:
    permissions:
      contents: read
      pull-requests: write
      issues: write
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v6

      - name: Assign labels based on paths
        uses: actions/labeler@main
        with:
          repo-token: "${{ secrets.GITHUB_TOKEN }}"
          sync-labels: true

      - name: Assign labels based on the PR's size
        uses: codelytv/pr-size-labeler@v1.10.3
        with:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          ignore_file_deletions: true
          xs_label: 'Size: XS'
          s_label: 'Size: S'
          m_label: 'Size: M'
          l_label: 'Size: L'
          xl_label: 'Size: XL'
```

# What's Next

TODO: It's complicated

Special Thanks to [__My Sponsors__](https://lupyuen.org/articles/sponsor) for supporting my writing. Your support means so much to me 🙏

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for Avaota-A1"__](https://github.com/lupyuen/nuttx-avaota-a1)

- [__Also My Current Project: "Apache NuttX RTOS for StarPro64 EIC7700X"__](https://github.com/lupyuen/nuttx-starpro64)

- [__My Other Project: "NuttX for Oz64 SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__Older Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/prtarget.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/prtarget.md)
