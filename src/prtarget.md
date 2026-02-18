# GitHub Actions pull_request_target vs Apache NuttX RTOS

📝 _1 Mar 2026_

![TODO](https://lupyuen.org/images/prtarget-title.jpg)

Guess why?

[.github/workflows/labeler.yml](https://github.com/apache/nuttx/blob/cf30528231a23c7329198bba220e8fcbac98baa2/.github/workflows/labeler.yml)

```yaml
## When a Pull Request is submitted...
on:
  - pull_request_target
jobs:
  labeler: ...
    steps:
      ## Checkout the repo
      - uses: actions/checkout@v6

      ## Assign the PR Labels based on the updated paths
      - uses: actions/labeler@main
        with:
          repo-token: "${{ secrets.GITHUB_TOKEN }}"
          sync-labels: true

      ## Assign the PR Labels based on the PR's size
      - uses: codelytv/pr-size-labeler@v1.10.3
        with:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

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
