# LLM Bot that reviews Pull Requests for Apache NuttX RTOS

📝 _30 Sep 2024_

![TODO](https://lupyuen.github.io/images/llm-title.jpg)

TODO

# PR Bot in Action

TODO

Suppose we [__Submit a Pull Request__](TODO) to the NuttX Repo...

<div style="margin-left: 5%; width: 90%; font-size:90%">

__Summary__ <br>
_Document stack and backtrace dump for Espressif SoCs [...more...]_

__Impact__ <br>
_Fix backtrace dump on assertions considering assertions triggered by tasks or during an interrupt service._

__Testing__ <br>
_Internal CI testing with HW on all Xtensa-based devices [...more...]_

[(Thanks to __Tiago Medicci Serrano__)](https://github.com/apache/nuttx/pull/13546)

</div>

Our PR Review Bot will helpfully __Review the Pull Request__ and post a Review Comment...

<div style="margin-left: 5%; width: 90%; font-size:90%">

_This PR appears to meet the NuttX requirements. Here's a breakdown:_

__Summary:__

- __Clear explanation of the change:__ The summary clearly states the purpose of the change, addressing a fix for the backtrace dump functionality specifically for Espressif SoCs _[...more...]_
- __Issue references:__ While not explicitly mentioned, the summary implies addressing an existing issue with backtrace dumps on the mentioned architectures. It would be beneficial to add specific issue references if applicable.

__Impact:__

- __Feature change:__ This PR focuses on fixing an existing feature (backtrace dump), not introducing a new one _[...more...]_
- __Security impact:__ No security implications are mentioned.
- __Compatibility impact:__ No backward or forward compatibility issues are mentioned.

__Testing:__

- __Verification:__ The author confirms testing on local setup with positive results.
- __Host and Target:__ While "Internal CI testing" is mentioned, listing specific host OS, compiler versions, and target boards used for testing would strengthen the validation _[...more...]_

__Overall:__

This PR demonstrates a good understanding of NuttX requirements. Adding specific issue references and detailing the testing environment would further strengthen it.

[(See the __Review Comment__)](TODO)

</div>

Hopefully this will be helpful to __New Contributors__ to NuttX. And it might help the __PR Reviewers__ too.

How did this happen? We find out...

# Requirements for PR Review

_Our Bot gets really chatty and naggy. Why?_

That's because we programmed it with a __Long List of Requirements__ for PR Review, in Markdown Format: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L24-L66)

<div style="margin-left: 5%; width: 90%; font-size:90%">

```rust
/// Requirements for PR Review
const REQUIREMENTS: &str =
r#####"
# Here are the requirements for a NuttX PR

## Summary

* Why change is necessary (fix, update, new feature)?
* What functional part of the code is being changed?
* How does the change exactly work (what will change and how)?
* Related [NuttX Issue](https://github.com/apache/nuttx/issues) reference if applicable.
* Related NuttX Apps [Issue](https://github.com/apache/nuttx-apps/issues) / [Pull Request](https://github.com/apache/nuttx-apps/pulls) reference if applicable.

## Impact

* Is new feature added? Is existing feature changed?
* Impact on user (will user need to adapt to change)? NO / YES (please describe if yes).
* Impact on build (will build process change)? NO / YES (please descibe if yes).
* Impact on hardware (will arch(s) / board(s) / driver(s) change)? NO / YES (please describe if yes).
* Impact on documentation (is update required / provided)? NO / YES (please describe if yes).
* Impact on security (any sort of implications)? NO / YES (please describe if yes).
* Impact on compatibility (backward/forward/interoperability)? NO / YES (please describe if yes).
* Anything else to consider?

## Testing

I confirm that changes are verified on local setup and works as intended:
* Build Host(s): OS (Linux,BSD,macOS,Windows,..), CPU(Intel,AMD,ARM), compiler(GCC,CLANG,version), etc.
* Target(s): arch(sim,RISC-V,ARM,..), board:config, etc.

Testing logs before change: _your testing logs here_

Testing logs after change: _your testing logs here_
"#####;
```

[(Thanks to __Tomek Cedro__)](TODO)

</div>

_But these are Human-Readable Requirements?_

That's the beauty of an LLM: We feed it the __Human Text__, then the LLM gets it (hopefully) and does what we expect it to do!

It helps to __define our requirements precisely__, mark the boundaries clearly. Otherwise our LLM will wander off, and hallucinate strange new ways to validate our Pull Request.

[(Which happened in our last __LLM Experiment__)](TODO)

_How do we feed the PR Content to LLM?_

Our PR Requirements are in __Markdown Format__. Same for the PR Content.

Thus we meld them together into __One Long Markdown Doc__ and feed to LLM: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L212-L218)

```rust
// Compose the Prompt for LLM Request:
// PR Requirements + PR Body
let input = 
  REQUIREMENTS.to_string() +
  "\n\n# Does this PR meet the NuttX Requirements? Please be concise\n\n" +
  &body;
```

Which will look like this...

```text
# Here are the requirements for a NuttX PR
## Summary [...requirements...]
## Impact [...requirements...]
## Testing [...requirements...]

# Does this PR meet the NuttX Requirements? Please be concise
## Summary
Document stack and backtrace dump for Espressif SoCs [...more...]

## Impact
Fix backtrace dump on assertions considering assertions triggered by tasks or during an interrupt service.

## Testing
Internal CI testing with HW on all Xtensa-based devices [...more...]
```

_Why "please be concise"?_

Based on [__Community Feedback__](TODO), our Bot was getting way too chatty and naggy.

It's hard to control the LLM Output, hence we politely asked LLM to __tone down the response__. (And be a little less irritating)

Also we excluded the Bot from Pull Requests that are [__Extra Small__](TODO). (10 lines of code changes or fewer)

_Will our Bot get stuck in a loop? Forever replying to its own responses?_

Nope it won't. Our Bot will skip [__Pull Requests that have Comments__](TODO).

# Call the Gemini API

TODO

We're using [__Gemini Pro 1.5__](TODO) for the LLM: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L205-L212)

```rust
// Init the Gemini Client (Pro 1.5)
let client = Client::new_from_model(
  Model::Gemini1_5Pro,
  env::var("GEMINI_API_KEY").unwrap().to_string()
);

// Compose the Prompt for Gemini Request:
// PR Requirements + PR Body
let input = 
  REQUIREMENTS.to_string() +
  "\n\n# Does this PR meet the NuttX Requirements? Please be concise\n\n" +
  &body;
```

[main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L212-L252)

```rust
// Compose the Gemini Request
let txt_request = Request {
  contents: vec![Content {
    role: Role::User,
    parts: vec![Part {
      text: Some(input.to_string()),
      inline_data: None,
      file_data: None,
      video_metadata: None,
    }],
  }],
  tools: vec![],
  safety_settings: vec![],
  generation_config: None,
  system_instruction: None,
};

// Send the Gemini Request
let response = client
  .post(30, &txt_request)
  .await?;

// Get the Gemini Response
let response_text = 
  response.rest().unwrap()
  .candidates.first().unwrap()
  .content.parts.first().unwrap()
  .text.clone().unwrap();
```

TODO: Gemini Pro 1.5, 50 requests per day, free tier

# Handle Gemini Failure

TODO

# GitHub API

TODO

# TODO

[run.sh](https://github.com/lupyuen/nuttx-pr-bot/blob/main/run.sh)

```bash
#!/usr/bin/env bash
## Handle PRs for NuttX Kernel and Apps every 10 minutes

## Update the repo
git pull

## Set the GitHub and Gemini Tokens
## export GITHUB_TOKEN=...
## export GEMINI_API_KEY=...
. $HOME/github-token.sh
. $HOME/gemini-token.sh

## Echo commands
set -x

## Enable Rust Logging
export RUST_LOG=info 
export RUST_BACKTRACE=1

## Handle PRs for NuttX Kernel and Apps every 10 minutes
for (( ; ; ))
do
  ## For NuttX Kernel Repo
  cargo run -- --owner apache --repo nuttx
  sleep 300

  ## For NuttX Apps Repo
  cargo run -- --owner apache --repo nuttx-apps
  sleep 300
done
```

See the [discussion for NuttX PR Review Bot](https://github.com/apache/nuttx/pull/13494#issuecomment-2357300091)

```bash
## See `run.sh` for the Complete Script

## Browse to Google AI Studio > Get API Key > Create API Key > Create API Key In New Project
## https://aistudio.google.com/app/apikey
export GEMINI_API_KEY=...

## GitHub Settings > Developer Settings > Tokens (Classic) > Generate New Token (Classic)
## Check the following:
## repo (Full control of private repositories)
## repo:status (Access commit status)
## repo_deployment (Access deployment status)
## public_repo (Access public repositories)
## repo:invite (Access repository invitations)
## security_events (Read and write security events)
export GITHUB_TOKEN=...

## Enable Rust Logging
export RUST_LOG=info 
export RUST_BACKTRACE=1

## Run the NuttX PR Bot once on NuttX Repo
cargo run -- --owner apache --repo nuttx

## Which will: Fetch the Latest 20 PRs
##   If PR Status = Open
##   And PR Comments don't exist
##     Then Call Gemini API to Validate the PR
##     And Post Gemini Response as PR Comment

## For NuttX Apps Repo
cargo run -- --owner apache --repo nuttx-apps
```

# Run Log

TODO

```text
+ cargo run --owner apache --repo nuttx
warning: use of deprecated method `octocrab::pulls::PullRequestHandler::<'octo>::pull_number`: specific PR builder transitioned to pr_review_actions, reply_to_comment, reply_to_comment
   --> src/main.rs:141:10
    |
141 |         .pull_number(pr_id)
    |          ^^^^^^^^^^^
    |
    = note: `#[warn(deprecated)]` on by default

warning: `nuttx-pr-bot` (bin "nuttx-pr-bot") generated 1 warning
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.18s
     Running `target/debug/nuttx-pr-bot`
[2024-09-20T07:47:40Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13554"
[2024-09-20T07:47:40Z INFO  nuttx_pr_bot] PR Body: "## Summary\r\ni2c: Optimize access to private data\r\n## Impact\r\ni2c_driver\r\n## Testing\r\nLocal iic testing\r\n"
[2024-09-20T07:47:47Z INFO  nuttx_pr_bot] Gemini Response: Rest(
        GeminiResponse {
            candidates: [
                Candidate {
                    content: Content {
                        role: Model,
                        parts: [
                            Part {
                                text: Some(
                                    "**No, this PR does not meet the NuttX requirements.**\n\n**Missing Information:**\n\n* **Summary:** \n    * Lacks a clear explanation of why the change is necessary. Is it a bug fix, performance improvement, or code cleanup?\n    * Doesn't describe the functional part of the code being changed within the i2c driver. \n    *  Missing details on how the optimization works. \n    *  No mention of related issues.\n* **Impact:**\n    * All impact sections are marked as \"i2c_driver,\" which is too vague.\n    *  The description should clearly state whether the impact is \"NO\" or \"YES\" and provide specific details if applicable. For example, does the change affect any specific architectures, boards, or drivers?\n* **Testing:**\n    * Lacks details about the local setup (host OS, target architecture, board configuration).\n    *  \"Local iic testing\" is insufficient. Provide specific test cases and commands used.\n    *  No testing logs provided. \n\n**To meet the NuttX requirements, the PR needs to provide comprehensive information in each section. ** \n",
                                ),
                                inline_data: None,
                                file_data: None,
                                video_metadata: None,
                            },
                        ],
                    },
                    finish_reason: Some(
                        "STOP",
                    ),
                    index: Some(
                        0,
                    ),
                    safety_ratings: [
                        SafetyRating {
                            category: HarmCategorySexuallyExplicit,
                            probability: Negligible,
                            blocked: false,
                        },
                        SafetyRating {
                            category: HarmCategoryHateSpeech,
                            probability: Negligible,
                            blocked: false,
                        },
                        SafetyRating {
                            category: HarmCategoryHarassment,
                            probability: Negligible,
                            blocked: false,
                        },
                        SafetyRating {
                            category: HarmCategoryDangerousContent,
                            probability: Negligible,
                            blocked: false,
                        },
                    ],
                },
            ],
            prompt_feedback: None,
            usage_metadata: Some(
                UsageMetadata {
                    prompt_token_count: 453,
                    candidates_token_count: 244,
                },
            ),
        },
    )
[2024-09-20T07:47:47Z INFO  nuttx_pr_bot] Response Text: "**No, this PR does not meet the NuttX requirements.**\n\n**Missing Information:**\n\n* **Summary:** \n    * Lacks a clear explanation of why the change is necessary. Is it a bug fix, performance improvement, or code cleanup?\n    * Doesn't describe the functional part of the code being changed within the i2c driver. \n    *  Missing details on how the optimization works. \n    *  No mention of related issues.\n* **Impact:**\n    * All impact sections are marked as \"i2c_driver,\" which is too vague.\n    *  The description should clearly state whether the impact is \"NO\" or \"YES\" and provide specific details if applicable. For example, does the change affect any specific architectures, boards, or drivers?\n* **Testing:**\n    * Lacks details about the local setup (host OS, target architecture, board configuration).\n    *  \"Local iic testing\" is insufficient. Provide specific test cases and commands used.\n    *  No testing logs provided. \n\n**To meet the NuttX requirements, the PR needs to provide comprehensive information in each section. ** \n"
[2024-09-20T07:47:48Z INFO  nuttx_pr_bot] PR Comment: Comment {
        id: CommentId(
            2363049923,
        ),
        node_id: "IC_kwDODZiUac6M2UfD",
        url: Url {
            scheme: "https",
            cannot_be_a_base: false,
            username: "",
            password: None,
            host: Some(
                Domain(
                    "api.github.com",
                ),
            ),
            port: None,
            path: "/repos/apache/nuttx/issues/comments/2363049923",
            query: None,
            fragment: None,
        },
        html_url: Url {
            scheme: "https",
            cannot_be_a_base: false,
            username: "",
            password: None,
            host: Some(
                Domain(
                    "github.com",
                ),
            ),
            port: None,
            path: "/apache/nuttx/pull/13554",
            query: None,
            fragment: Some(
                "issuecomment-2363049923",
            ),
        },
        issue_url: Some(
            Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/repos/apache/nuttx/issues/13554",
                query: None,
                fragment: None,
            },
        ),
        body: Some(
            "[**\\[Experimental Bot, please feedback here\\]**](https://github.com/search?q=repo%3Aapache%2Fnuttx+13552&type=issues)\n\n\n\n**No, this PR does not meet the NuttX requirements.**\n\n**Missing Information:**\n\n* **Summary:** \n    * Lacks a clear explanation of why the change is necessary. Is it a bug fix, performance improvement, or code cleanup?\n    * Doesn't describe the functional part of the code being changed within the i2c driver. \n    *  Missing details on how the optimization works. \n    *  No mention of related issues.\n* **Impact:**\n    * All impact sections are marked as \"i2c_driver,\" which is too vague.\n    *  The description should clearly state whether the impact is \"NO\" or \"YES\" and provide specific details if applicable. For example, does the change affect any specific architectures, boards, or drivers?\n* **Testing:**\n    * Lacks details about the local setup (host OS, target architecture, board configuration).\n    *  \"Local iic testing\" is insufficient. Provide specific test cases and commands used.\n    *  No testing logs provided. \n\n**To meet the NuttX requirements, the PR needs to provide comprehensive information in each section. ** \n",
        ),
        body_text: None,
        body_html: None,
        author_association: None,
        user: Author {
            login: "nuttxpr",
            id: UserId(
                181999181,
            ),
            node_id: "U_kgDOCtkWTQ",
            avatar_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "avatars.githubusercontent.com",
                    ),
                ),
                port: None,
                path: "/u/181999181",
                query: Some(
                    "v=4",
                ),
                fragment: None,
            },
            gravatar_id: "",
            url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr",
                query: None,
                fragment: None,
            },
            html_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "github.com",
                    ),
                ),
                port: None,
                path: "/nuttxpr",
                query: None,
                fragment: None,
            },
            followers_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/followers",
                query: None,
                fragment: None,
            },
            following_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/following%7B/other_user%7D",
                query: None,
                fragment: None,
            },
            gists_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/gists%7B/gist_id%7D",
                query: None,
                fragment: None,
            },
            starred_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/starred%7B/owner%7D%7B/repo%7D",
                query: None,
                fragment: None,
            },
            subscriptions_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/subscriptions",
                query: None,
                fragment: None,
            },
            organizations_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/orgs",
                query: None,
                fragment: None,
            },
            repos_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/repos",
                query: None,
                fragment: None,
            },
            events_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/events%7B/privacy%7D",
                query: None,
                fragment: None,
            },
            received_events_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/received_events",
                query: None,
                fragment: None,
            },
            type: "User",
            site_admin: false,
            patch_url: None,
            email: None,
        },
        created_at: 2024-09-20T07:47:47Z,
        updated_at: Some(
            2024-09-20T07:47:47Z,
        ),
    }
[2024-09-20T07:47:49Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13554"
[2024-09-20T07:48:54Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13553"
[2024-09-20T07:48:54Z INFO  nuttx_pr_bot] PR Body: "## Summary\r\nnuttx add pci ep framework\r\n## Impact\r\n\r\n## Testing\r\n\r\n"
[2024-09-20T07:49:04Z INFO  nuttx_pr_bot] Gemini Response: Rest(
        GeminiResponse {
            candidates: [
                Candidate {
                    content: Content {
                        role: Model,
                        parts: [
                            Part {
                                text: Some(
                                    "**No, this PR does not meet the NuttX requirements.**\n\n**Summary:**\n\n* **Insufficient information:** The summary is too brief and lacks essential details. It doesn't explain:\n    * **Necessity:** Why is the PCI EP framework needed? What problem does it solve, or what improvement does it bring?\n    * **Functionality:** Which part of the codebase is affected? What specific PCI EP capabilities are being added?\n    * **Implementation:** How does the framework work? What changes have been made to the code?\n* **Missing references:**  Are there related NuttX issues or NuttX Apps issues/pull requests?\n\n**Impact:**\n\n* **Entirely missing:** The impact section is empty.  You must address all the points to demonstrate a thorough understanding of your changes.\n\n**Testing:**\n\n* **No details provided:** \n    *  You need to list the specific build hosts (OS, CPU, compiler) and target devices (architecture, board, configuration) where you tested the changes.\n    *  Provide actual testing logs from **before** and **after** the change to show the difference in behavior.\n\n**To improve this PR:**\n\n1. **Expand the Summary:** Provide a clear and detailed explanation of the changes, their purpose, and how they are implemented.\n2. **Complete the Impact section:** Analyze and describe the impact of your changes on all the listed aspects (user, build, hardware, documentation, security, compatibility).\n3. **Provide Testing Details:** Specify your build hosts and target devices, and include relevant testing logs from before and after applying your changes.\n\n**By addressing these points, your PR will be far more likely to be reviewed and merged.** \n",
                                ),
                                inline_data: None,
                                file_data: None,
                                video_metadata: None,
                            },
                        ],
                    },
                    finish_reason: Some(
                        "STOP",
                    ),
                    index: Some(
                        0,
                    ),
                    safety_ratings: [
                        SafetyRating {
                            category: HarmCategorySexuallyExplicit,
                            probability: Negligible,
                            blocked: false,
                        },
                        SafetyRating {
                            category: HarmCategoryHateSpeech,
                            probability: Negligible,
                            blocked: false,
                        },
                        SafetyRating {
                            category: HarmCategoryHarassment,
                            probability: Negligible,
                            blocked: false,
                        },
                        SafetyRating {
                            category: HarmCategoryDangerousContent,
                            probability: Negligible,
                            blocked: false,
                        },
                    ],
                },
            ],
            prompt_feedback: None,
            usage_metadata: Some(
                UsageMetadata {
                    prompt_token_count: 441,
                    candidates_token_count: 358,
                },
            ),
        },
    )
[2024-09-20T07:49:04Z INFO  nuttx_pr_bot] Response Text: "**No, this PR does not meet the NuttX requirements.**\n\n**Summary:**\n\n* **Insufficient information:** The summary is too brief and lacks essential details. It doesn't explain:\n    * **Necessity:** Why is the PCI EP framework needed? What problem does it solve, or what improvement does it bring?\n    * **Functionality:** Which part of the codebase is affected? What specific PCI EP capabilities are being added?\n    * **Implementation:** How does the framework work? What changes have been made to the code?\n* **Missing references:**  Are there related NuttX issues or NuttX Apps issues/pull requests?\n\n**Impact:**\n\n* **Entirely missing:** The impact section is empty.  You must address all the points to demonstrate a thorough understanding of your changes.\n\n**Testing:**\n\n* **No details provided:** \n    *  You need to list the specific build hosts (OS, CPU, compiler) and target devices (architecture, board, configuration) where you tested the changes.\n    *  Provide actual testing logs from **before** and **after** the change to show the difference in behavior.\n\n**To improve this PR:**\n\n1. **Expand the Summary:** Provide a clear and detailed explanation of the changes, their purpose, and how they are implemented.\n2. **Complete the Impact section:** Analyze and describe the impact of your changes on all the listed aspects (user, build, hardware, documentation, security, compatibility).\n3. **Provide Testing Details:** Specify your build hosts and target devices, and include relevant testing logs from before and after applying your changes.\n\n**By addressing these points, your PR will be far more likely to be reviewed and merged.** \n"
[2024-09-20T07:49:04Z INFO  nuttx_pr_bot] PR Comment: Comment {
        id: CommentId(
            2363052015,
        ),
        node_id: "IC_kwDODZiUac6M2U_v",
        url: Url {
            scheme: "https",
            cannot_be_a_base: false,
            username: "",
            password: None,
            host: Some(
                Domain(
                    "api.github.com",
                ),
            ),
            port: None,
            path: "/repos/apache/nuttx/issues/comments/2363052015",
            query: None,
            fragment: None,
        },
        html_url: Url {
            scheme: "https",
            cannot_be_a_base: false,
            username: "",
            password: None,
            host: Some(
                Domain(
                    "github.com",
                ),
            ),
            port: None,
            path: "/apache/nuttx/pull/13553",
            query: None,
            fragment: Some(
                "issuecomment-2363052015",
            ),
        },
        issue_url: Some(
            Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/repos/apache/nuttx/issues/13553",
                query: None,
                fragment: None,
            },
        ),
        body: Some(
            "[**\\[Experimental Bot, please feedback here\\]**](https://github.com/search?q=repo%3Aapache%2Fnuttx+13552&type=issues)\n\n__Squash The Commits:__ This PR contains 6 Commits. Please Squash the Multiple Commits into a Single Commit.\n\n\n\n**No, this PR does not meet the NuttX requirements.**\n\n**Summary:**\n\n* **Insufficient information:** The summary is too brief and lacks essential details. It doesn't explain:\n    * **Necessity:** Why is the PCI EP framework needed? What problem does it solve, or what improvement does it bring?\n    * **Functionality:** Which part of the codebase is affected? What specific PCI EP capabilities are being added?\n    * **Implementation:** How does the framework work? What changes have been made to the code?\n* **Missing references:**  Are there related NuttX issues or NuttX Apps issues/pull requests?\n\n**Impact:**\n\n* **Entirely missing:** The impact section is empty.  You must address all the points to demonstrate a thorough understanding of your changes.\n\n**Testing:**\n\n* **No details provided:** \n    *  You need to list the specific build hosts (OS, CPU, compiler) and target devices (architecture, board, configuration) where you tested the changes.\n    *  Provide actual testing logs from **before** and **after** the change to show the difference in behavior.\n\n**To improve this PR:**\n\n1. **Expand the Summary:** Provide a clear and detailed explanation of the changes, their purpose, and how they are implemented.\n2. **Complete the Impact section:** Analyze and describe the impact of your changes on all the listed aspects (user, build, hardware, documentation, security, compatibility).\n3. **Provide Testing Details:** Specify your build hosts and target devices, and include relevant testing logs from before and after applying your changes.\n\n**By addressing these points, your PR will be far more likely to be reviewed and merged.** \n",
        ),
        body_text: None,
        body_html: None,
        author_association: None,
        user: Author {
            login: "nuttxpr",
            id: UserId(
                181999181,
            ),
            node_id: "U_kgDOCtkWTQ",
            avatar_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "avatars.githubusercontent.com",
                    ),
                ),
                port: None,
                path: "/u/181999181",
                query: Some(
                    "v=4",
                ),
                fragment: None,
            },
            gravatar_id: "",
            url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr",
                query: None,
                fragment: None,
            },
            html_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "github.com",
                    ),
                ),
                port: None,
                path: "/nuttxpr",
                query: None,
                fragment: None,
            },
            followers_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/followers",
                query: None,
                fragment: None,
            },
            following_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/following%7B/other_user%7D",
                query: None,
                fragment: None,
            },
            gists_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/gists%7B/gist_id%7D",
                query: None,
                fragment: None,
            },
            starred_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/starred%7B/owner%7D%7B/repo%7D",
                query: None,
                fragment: None,
            },
            subscriptions_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/subscriptions",
                query: None,
                fragment: None,
            },
            organizations_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/orgs",
                query: None,
                fragment: None,
            },
            repos_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/repos",
                query: None,
                fragment: None,
            },
            events_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/events%7B/privacy%7D",
                query: None,
                fragment: None,
            },
            received_events_url: Url {
                scheme: "https",
                cannot_be_a_base: false,
                username: "",
                password: None,
                host: Some(
                    Domain(
                        "api.github.com",
                    ),
                ),
                port: None,
                path: "/users/nuttxpr/received_events",
                query: None,
                fragment: None,
            },
            type: "User",
            site_admin: false,
            patch_url: None,
            email: None,
        },
        created_at: 2024-09-20T07:49:04Z,
        updated_at: Some(
            2024-09-20T07:49:04Z,
        ),
    }
[2024-09-20T07:49:05Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13553"
[2024-09-20T07:50:11Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13551"
[2024-09-20T07:50:11Z INFO  nuttx_pr_bot] Skipping PR with comments: 13551
[2024-09-20T07:50:16Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13550"
[2024-09-20T07:50:16Z INFO  nuttx_pr_bot] Skipping PR with comments: 13550
[2024-09-20T07:50:22Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13549"
[2024-09-20T07:50:22Z INFO  nuttx_pr_bot] Skipping PR with comments: 13549
[2024-09-20T07:50:27Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13546"
[2024-09-20T07:50:27Z INFO  nuttx_pr_bot] Skipping PR with comments: 13546
[2024-09-20T07:50:33Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13545"
[2024-09-20T07:50:33Z INFO  nuttx_pr_bot] Skipping PR with comments: 13545
[2024-09-20T07:50:38Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13541"
[2024-09-20T07:50:38Z INFO  nuttx_pr_bot] Skipping PR with comments: 13541
[2024-09-20T07:50:43Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13539"
[2024-09-20T07:50:43Z INFO  nuttx_pr_bot] Skipping PR with comments: 13539
[2024-09-20T07:50:49Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13538"
[2024-09-20T07:50:49Z INFO  nuttx_pr_bot] Skipping PR with comments: 13538
[2024-09-20T07:50:54Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13536"
[2024-09-20T07:50:54Z INFO  nuttx_pr_bot] Skipping PR with comments: 13536
[2024-09-20T07:51:00Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13530"
[2024-09-20T07:51:00Z INFO  nuttx_pr_bot] Skipping PR with comments: 13530
[2024-09-20T07:51:05Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13527"
[2024-09-20T07:51:05Z INFO  nuttx_pr_bot] Skipping PR with comments: 13527
[2024-09-20T07:51:11Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13526"
[2024-09-20T07:51:11Z INFO  nuttx_pr_bot] Skipping PR with comments: 13526
[2024-09-20T07:51:16Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13520"
[2024-09-20T07:51:16Z INFO  nuttx_pr_bot] Skipping PR with comments: 13520
[2024-09-20T07:51:22Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13519"
[2024-09-20T07:51:22Z INFO  nuttx_pr_bot] Skipping PR with comments: 13519
[2024-09-20T07:51:27Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13518"
[2024-09-20T07:51:27Z INFO  nuttx_pr_bot] Skipping PR with comments: 13518
[2024-09-20T07:51:33Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13507"
[2024-09-20T07:51:33Z INFO  nuttx_pr_bot] Skipping PR with comments: 13507
[2024-09-20T07:51:38Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13502"
[2024-09-20T07:51:38Z INFO  nuttx_pr_bot] Skipping PR with comments: 13502
[2024-09-20T07:51:43Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13498"
[2024-09-20T07:51:43Z INFO  nuttx_pr_bot] Skipping PR with comments: 13498
+ sleep 600
+ (( 1 ))
+ (( 1 ))
+ cargo run --owner apache --repo nuttx
warning: use of deprecated method `octocrab::pulls::PullRequestHandler::<'octo>::pull_number`: specific PR builder transitioned to pr_review_actions, reply_to_comment, reply_to_comment
   --> src/main.rs:141:10
    |
141 |         .pull_number(pr_id)
    |          ^^^^^^^^^^^
    |
    = note: `#[warn(deprecated)]` on by default

warning: `nuttx-pr-bot` (bin "nuttx-pr-bot") generated 1 warning
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.17s
     Running `target/debug/nuttx-pr-bot`
[2024-09-20T08:01:50Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13555"
[2024-09-20T08:01:50Z INFO  nuttx_pr_bot] Skipping PR Size XS: 13555
[2024-09-20T08:01:56Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13554"
[2024-09-20T08:01:56Z INFO  nuttx_pr_bot] Skipping PR with comments: 13554
[2024-09-20T08:02:01Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13553"
[2024-09-20T08:02:01Z INFO  nuttx_pr_bot] Skipping PR with comments: 13553
[2024-09-20T08:02:06Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13551"
[2024-09-20T08:02:06Z INFO  nuttx_pr_bot] Skipping PR with comments: 13551
[2024-09-20T08:02:12Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13550"
[2024-09-20T08:02:12Z INFO  nuttx_pr_bot] Skipping PR with comments: 13550
[2024-09-20T08:02:17Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13549"
[2024-09-20T08:02:17Z INFO  nuttx_pr_bot] Skipping PR with comments: 13549
[2024-09-20T08:02:23Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13546"
[2024-09-20T08:02:23Z INFO  nuttx_pr_bot] Skipping PR with comments: 13546
[2024-09-20T08:02:28Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13545"
[2024-09-20T08:02:28Z INFO  nuttx_pr_bot] Skipping PR with comments: 13545
[2024-09-20T08:02:34Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13541"
[2024-09-20T08:02:34Z INFO  nuttx_pr_bot] Skipping PR with comments: 13541
[2024-09-20T08:02:39Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13539"
[2024-09-20T08:02:39Z INFO  nuttx_pr_bot] Skipping PR with comments: 13539
[2024-09-20T08:02:45Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13538"
[2024-09-20T08:02:45Z INFO  nuttx_pr_bot] Skipping PR with comments: 13538
[2024-09-20T08:02:50Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13536"
[2024-09-20T08:02:50Z INFO  nuttx_pr_bot] Skipping PR with comments: 13536
[2024-09-20T08:02:56Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13530"
[2024-09-20T08:02:56Z INFO  nuttx_pr_bot] Skipping PR with comments: 13530
[2024-09-20T08:03:02Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13527"
[2024-09-20T08:03:02Z INFO  nuttx_pr_bot] Skipping PR with comments: 13527
[2024-09-20T08:03:07Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13526"
[2024-09-20T08:03:07Z INFO  nuttx_pr_bot] Skipping PR with comments: 13526
[2024-09-20T08:03:13Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13520"
[2024-09-20T08:03:13Z INFO  nuttx_pr_bot] Skipping PR with comments: 13520
[2024-09-20T08:03:18Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13519"
[2024-09-20T08:03:18Z INFO  nuttx_pr_bot] Skipping PR with comments: 13519
[2024-09-20T08:03:24Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13518"
[2024-09-20T08:03:24Z INFO  nuttx_pr_bot] Skipping PR with comments: 13518
[2024-09-20T08:03:29Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13507"
[2024-09-20T08:03:29Z INFO  nuttx_pr_bot] Skipping PR with comments: 13507
[2024-09-20T08:03:35Z INFO  nuttx_pr_bot] "https://api.github.com/repos/apache/nuttx/pulls/13502"
[2024-09-20T08:03:35Z INFO  nuttx_pr_bot] Skipping PR with comments: 13502
+ sleep 600  
```

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Sophgo SG2000"__](https://github.com/lupyuen/nuttx-sg2000)

-   [__My Other Project: "NuttX for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__Older Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Olderer Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/llm.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/llm.md)
