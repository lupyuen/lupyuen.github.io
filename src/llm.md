# LLM Bot that reviews Pull Requests for Apache NuttX RTOS

📝 _29 Sep 2024_

![LLM Bot that reviews Pull Requests for Apache NuttX RTOS](https://lupyuen.github.io/images/llm-flow.jpg)

We're experimenting with an __LLM Bot__ (Large Language Model) that will review Pull Requests for [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html).

This article explains how we created the LLM Bot in One Week...

- We call the __GitHub API__ to fetch NuttX Pull Requests

- Append the PR Body to the __NuttX PR Requirements__

- Which becomes the __LLM Prompt__ that we send to __Gemini API__

- Our Bot posts the Gemini Response as a __PR Review Comment__

- Due to quirks in the Gemini API: We use __Emoji Reactions__ to limit the API Calls

- Though our LLM Bot was created by __Sheer Accident__

  (It wasn't meant to be an AI Project!)

![Pull Request for NuttX Repo](https://lupyuen.github.io/images/llm-pr.jpg)

# PR Bot in Action

Suppose we [__Submit a Pull Request__](https://github.com/apache/nuttx/pulls) to the NuttX Repo (pic above)...

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

[(See the __Review Comment__)](https://github.com/apache/nuttx/pull/13546#issuecomment-2361854435)

</div>

Hopefully this will be helpful to __New Contributors__ to NuttX. And it might help the __PR Reviewers__ too.

What just happened? We find out...

![Requirements for PR Review](https://lupyuen.github.io/images/llm-flow2.jpg)

# Requirements for PR Review

_Our Bot gets really chatty and naggy. Why?_

That's because we programmed it with a __Long List of Requirements__ for PR Review (pic above), in Markdown Format: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L24-L66)

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

[(Thanks to __Tomek Cedro__)](https://github.com/apache/nuttx/pull/13494)

</div>

_But these are Human-Readable Requirements?_

That's the beauty of an LLM: We feed it the __Human Text__, then the LLM gets it (hopefully) and does what we expect it to do!

It helps to __define our requirements precisely__, mark the boundaries clearly. Otherwise our LLM will wander off, and hallucinate strange new ways to validate our Pull Request.

[(Which happened in our last __LLM Experiment__)](https://lupyuen.github.io/articles/chatgpt)

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

Based on [__Community Feedback__](https://github.com/apache/nuttx/pull/13494#issuecomment-2360421272), our Bot was getting way too chatty and naggy.

It's hard to control the LLM Output, hence we politely asked LLM to __tone down the response__. (And be a little less irritating)

Also we excluded the Bot from Pull Requests that are [__Extra Small__](https://lupyuen.github.io/articles/llm#call-the-github-api). (10 lines of code changes or fewer)

_Will our Bot get stuck in a loop? Forever replying to its own responses?_

Nope it won't. Our Bot will skip [__Pull Requests that have Comments__](https://lupyuen.github.io/articles/llm#call-the-github-api).

![Call the Gemini LLM](https://lupyuen.github.io/images/llm-flow3.jpg)

# Call the Gemini LLM

_How are we running the LLM?_

We call [__Gemini Pro 1.5__](https://ai.google.dev/gemini-api/docs) for the LLM: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L205-L212)

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

[(Thanks to __google-generative-ai-rs__)](https://github.com/avastmick/google-generative-ai-rs)

After composing the __LLM Prompt__ (PR Requirements + PR Contents), we send it to Gemini: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L212-L252)

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

__Gemini Response__ will be in Markdown Format (pic above)...

<div style="margin-left: 5%; width: 90%; font-size:90%">

```text
## NuttX PR Requirements Review

This PR appears to meet the NuttX requirements. Here's a breakdown:

**Summary:**

* **Clear explanation of the change:** The summary clearly states the purpose of the change, addressing a fix for the backtrace dump functionality specifically for Espressif SoCs. 
* **Functional area:**  The affected area is clearly identified (stack and backtrace dump for xtensa/esp32).
* **Mechanism:**  The summary outlines how the change works, including fixes to the `MAKE_PC_FROM_RA` macro, sanity checks, and script updates.
* **Issue references:** While not explicitly mentioned, the summary implies addressing an existing issue with backtrace dumps on the mentioned architectures. It would be beneficial to add specific issue references if applicable.

**Impact:**

* **Feature change:** This PR focuses on fixing an existing feature (backtrace dump), not introducing a new one.
* **User impact:** No user-facing changes are described, implying minimal impact.
* **Build impact:** No build process changes are mentioned.
* **Hardware impact:** The changes are specific to Xtensa-based devices, specifically ESP32 and its variants, which is clearly stated.
* **Documentation impact:** The summary explicitly mentions updating documentation for each affected chip. 
* **Security impact:** No security implications are mentioned.
* **Compatibility impact:**  No backward or forward compatibility issues are mentioned.

**Testing:**

* **Verification:** The author confirms testing on local setup with positive results. 
* **Host and Target:**  While "Internal CI testing" is mentioned,  listing specific host OS, compiler versions, and target boards used for testing would strengthen the validation.
* **Logs:** The PR provides clear steps to reproduce the issue and verify the fix on an ESP32. Including snippets of actual logs before and after the change would further enhance the testing section.

**Overall:**

This PR demonstrates a good understanding of NuttX requirements.  Adding specific issue references and detailing the testing environment would further strengthen it. 
```

[(See the __Gemini Response__)](https://github.com/apache/nuttx/pull/13546#issuecomment-2361854435)

</div>

_But we didn't tell Gemini to respond in Markdown?_

That's the law of __"LLM See, LLM Do"__! We fed the input in Markdown Format, so it produced the output in Markdown Format too.

![Gemini Pro 1.5 limits us to 50 LLM Requests per day](https://lupyuen.github.io/images/llm-quota.png)

_Are we paying Google for the LLM?_

Right now we call the __Free Tier__ of Gemini Pro 1.5. Which limits us to [__50 LLM Requests__](https://ai.google.dev/pricing) per day. (Pic above)

That's sufficient to review __50 Pull Requests__ for NuttX every day. (For both the [__NuttX Kernel Repo__](https://github.com/apache/nuttx/pulls) and the [__NuttX Apps Repo__](https://github.com/apache/nuttx-apps/pulls))

![Fail Gracefully with Emojis](https://lupyuen.github.io/images/llm-emoji.jpg)

# Fail Gracefully with Emojis

_Any gotchas with the Free Tier of Gemini LLM?_

Gemini API will __sometimes fail__ with HTTP 500 (not sure why). And the Failed Request will be __counted in our Daily Quota__! (50 per day)

Thus we retry __up to 3 times__, in case the Pull Request has some problematic text that the LLM couldn't handle.

_How does our Bot know when to stop the retries?_

Our Bot uses __Emoji Reactions__ (pic above) to tag each attempt. We'll see the Pull Request tagged with...

|||
|----|---------------|
| 🚀 | _First Attempt_ |
| 👀 | _Second Attempt_ |
| 🚀👀 | _Third Attempt_ |

<br> Then our Bot gives up. If it's hunky dory, our Bot erases its Emoji Reactions. Everything happens here: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L306-L320)

```rust
/// Bump up the 2 PR Reactions: 00 > 01 > 10 > 11
/// Position 0 is the Rocket Reaction, Position 1 is the Eye Reaction
async fn bump_reactions(issues: &IssueHandler<'_>, pr_id: u64, reactions: (Option<u64>, Option<u64>)) -> Result<(), Box<dyn std::error::Error>> {
  match reactions {
    // (Rocket, Eye)
    (None,     None)    => { create_reaction(issues, pr_id, ReactionContent::Rocket).await?; }
    (Some(id), None)    => { delete_reaction(issues, pr_id, id).await?; create_reaction(issues, pr_id, ReactionContent::Eyes).await?; }
    (None,     Some(_)) => { create_reaction(issues, pr_id, ReactionContent::Rocket).await?; }
    (Some(_),  Some(_)) => { panic!("Reaction Overflow") }
  }
  Ok(())
}
```

[(__create_reaction__ is here)](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L333-L341)

[(__delete_reaction__ is here)](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L341-L348)

![Call the GitHub API](https://lupyuen.github.io/images/llm-flow4.jpg)

# Call the GitHub API

_How do we fetch the Pull Request? And post the Review Comment?_

We call GitHub API with [__Octocrab Crate__](https://github.com/XAMPPRocky/octocrab). (Pic above)

Here we fetch the __20 Newest Pull Requests__ that are Open: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L97-L115)

```rust
// Fetch the 20 Newest Pull Requests that are Open
let pr_list = octocrab
  .pulls(owner, repo)
  .list()
  .state(params::State::Open)
  .sort(params::pulls::Sort::Created)
  .direction(params::Direction::Descending)
  .per_page(20)
  .send()
  .await?;

// Every 5 Seconds: Process the next PR fetched
for pr in pr_list {
  let pr_id = pr.number;
  process_pr(&pulls, &issues, pr_id)
    .await?;
  sleep(Duration::from_secs(5));
}
```

__process_pr__ will read the PR Content: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L119-L194)

```rust
// Skip if PR contains Comments
if pr.comments.unwrap() > 0 { return Ok(()); }

// Skip if PR Size is Unknown or Extra Small
let labels = pr.labels.unwrap();
let size_xs: Vec<Label> = labels
  .into_iter()
  .filter(|l| l.name == "Size: XS")
  .collect();
if labels.is_empty() || size_xs.len() > 0 { return Ok(()); }

// Get the PR Body
let body = pr.body.unwrap_or("".to_string());

// Fetch the PR Commits. TODO: Will change `pull_number` to `pr_commits`
let commits = octocrab
  .pulls(owner, repo);
  .pull_number(pr_id)
  .commits()
  .await;
let commits = commits.unwrap().items;

// Omitted: Check for Empty Commit Message
```

Then we __Validate the PR Content__ with Gemini API and post the Gemini Response: [main.rs](https://github.com/lupyuen/nuttx-pr-bot/blob/main/src/main.rs#L261-L267)

```rust
// Omitted: Validate PR Body with Gemini LLM
...
// Post the PR Comment
let comment = octocrab
  .issues(owner, repo);
  .create_comment(pr_id, comment_text)
  .await?;
```

![Pull Request for NuttX Repo](https://lupyuen.github.io/images/llm-pr.jpg)

# Run The Bot

_How to run our PR Review Bot?_

This will run our __PR Review Bot__ to handle Pull Requests for NuttX Kernel Repo and NuttX Apps Repo, every 10 minutes: [run.sh](https://github.com/lupyuen/nuttx-pr-bot/blob/main/run.sh)

```bash
## For Gemini Token: Browse to Google AI Studio > Get API Key > Create API Key > Create API Key In New Project
## https://aistudio.google.com/app/apikey
export GEMINI_API_KEY=...

## For GitHub Token: Browse to GitHub Settings > Developer Settings > Tokens (Classic) > Generate New Token (Classic)
## Check the following:
## repo (Full control of private repositories)
## repo:status (Access commit status)
## repo_deployment (Access deployment status)
## public_repo (Access public repositories)
## repo:invite (Access repository invitations)
## security_events (Read and write security events)
export GITHUB_TOKEN=...

## Show the logs
set -x
export RUST_LOG=info 
export RUST_BACKTRACE=1

## Download our PR Review Bot
git clone https://github.com/lupyuen/nuttx-pr-bot
cd nuttx-pr-bot

## Handle PRs for NuttX Kernel and Apps every 10 minutes
for (( ; ; ))
do
  ## For NuttX Kernel Repo: github.com/apache/nuttx
  cargo run -- --owner apache --repo nuttx
  sleep 300

  ## For NuttX Apps Repo: github.com/apache/nuttx-apps
  cargo run -- --owner apache --repo nuttx-apps
  sleep 300
done
```

[(Any GitHub ID will do. Don't use a __Privileged GitHub ID__!)](https://github.com/apache/nuttx/pull/13494#issuecomment-2358374720)

We'll see this...

```bash
$ cargo run --owner apache --repo nuttx
warning: use of deprecated method `octocrab::pulls::PullRequestHandler::<'octo>::pull_number`: specific PR builder transitioned to pr_review_actions, reply_to_comment, reply_to_comment
  --> src/main.rs:141:10
141 |         .pull_number(pr_id)
Running `target/debug/nuttx-pr-bot`

https://api.github.com/repos/apache/nuttx/pulls/13554
PR Body:
  "## Summary\r\ni2c: Optimize access to private data\r\n## Impact\r\ni2c_driver\r\n## Testing\r\nLocal iic testing\r\n"
  ...
Gemini Response:
  Rest(GeminiResponse {candidates: [Candidate {content: Content role: Model,parts: [Part {text: Some(
  "**No, this PR does not meet the NuttX requirements.**\n\n**Missing Information:**\n\n* **Summary:** \n    * Lacks a clear explanation of why the change is necessary. Is it a bug fix, performance improvement, or code cleanup?\n    * Doesn't describe the functional part of the code being changed within the i2c driver. \n    *  Missing details on how the optimization works. \n    *  No mention of related issues.\n* **Impact:**\n    * All impact sections are marked as \"i2c_driver,\" which is too vague.\n    *  The description should clearly state whether the impact is \"NO\" or \"YES\" and provide specific details if applicable. For example, does the change affect any specific architectures, boards, or drivers?\n* **Testing:**\n    * Lacks details about the local setup (host OS, target architecture, board configuration).\n    *  \"Local iic testing\" is insufficient. Provide specific test cases and commands used.\n    *  No testing logs provided. \n\n**To meet the NuttX requirements, the PR needs to provide comprehensive information in each section. ** \n"),
  ...
Response Text:
  "**No, this PR does not meet the NuttX requirements.**\n\n**Missing Information:**\n\n* **Summary:** \n    * Lacks a clear explanation of why the change is necessary. Is it a bug fix, performance improvement, or code cleanup?\n    * Doesn't describe the functional part of the code being changed within the i2c driver. \n    *  Missing details on how the optimization works. \n    *  No mention of related issues.\n* **Impact:**\n    * All impact sections are marked as \"i2c_driver,\" which is too vague.\n    *  The description should clearly state whether the impact is \"NO\" or \"YES\" and provide specific details if applicable. For example, does the change affect any specific architectures, boards, or drivers?\n* **Testing:**\n    * Lacks details about the local setup (host OS, target architecture, board configuration).\n    *  \"Local iic testing\" is insufficient. Provide specific test cases and commands used.\n    *  No testing logs provided. \n\n**To meet the NuttX requirements, the PR needs to provide comprehensive information in each section. ** \n"
  ...
PR Comment:
  Comment {body: Some(
  "[**\\[Experimental Bot, please feedback here\\]**](https://github.com/search?q=repo%3Aapache%2Fnuttx+13552&type=issues)\n\n\n\n**No, this PR does not meet the NuttX requirements.**\n\n**Missing Information:**\n\n* **Summary:** \n    * Lacks a clear explanation of why the change is necessary. Is it a bug fix, performance improvement, or code cleanup?\n    * Doesn't describe the functional part of the code being changed within the i2c driver. \n    *  Missing details on how the optimization works. \n    *  No mention of related issues.\n* **Impact:**\n    * All impact sections are marked as \"i2c_driver,\" which is too vague.\n    *  The description should clearly state whether the impact is \"NO\" or \"YES\" and provide specific details if applicable. For example, does the change affect any specific architectures, boards, or drivers?\n* **Testing:**\n    * Lacks details about the local setup (host OS, target architecture, board configuration).\n    *  \"Local iic testing\" is insufficient. Provide specific test cases and commands used.\n    *  No testing logs provided. \n\n**To meet the NuttX requirements, the PR needs to provide comprehensive information in each section. ** \n",),
  ...
https://api.github.com/repos/apache/nuttx/pulls/13551
Skipping PR with comments: 13551
```

[(See the __Complete Log__)](https://github.com/lupyuen/nuttx-pr-bot?tab=readme-ov-file#run-log)

![LLM Bot that reviews Pull Requests for Apache NuttX RTOS](https://lupyuen.github.io/images/llm-flow.jpg)

# All Things Considered

_Something sounds super feeeshy about this AI Project? Very Hangyodon..._

That's because it was __never meant__ to be an AI Project!

- A bunch of us discussed the [__New Template__](https://github.com/apache/nuttx/pull/13494#issue-2528631514) for NuttX Pull Requests

- But the New Template might be too [__onerous to enforce__](https://github.com/apache/nuttx/pull/13494#issuecomment-2354153887)

- Then by sheer accident we thought: Why don't we let the [__machine enforce it__](https://github.com/apache/nuttx/pull/13494#issuecomment-2355202046)? (Thus the LLM and AI)

- Or maybe we hallucinated the AI after a [__50 km overnight hike__](https://www.strava.com/activities/12427941691)

_How effective is our Bot in enforcing the PR Requirements?_

We're still monitoring? Our Bot seems helpful for newer NuttX Contributors, we noticed [__better quality__](https://github.com/apache/nuttx/pull/13494#issuecomment-2365235765) in some Pull Requests.

Then again, our Bot might be [__too intimidating__](https://github.com/apache/nuttx/pull/13523) for some folks.

_Is LLM the right tech for the job?_

LLM has limitations...

- We see [__inconsistency in the outputs__](https://github.com/apache/nuttx/issues/13552#issuecomment-2367958326). Yet we can't force the output.

- Sometimes the LLM will helpfully suggest [__"Example Improvements"__](https://github.com/apache/nuttx/pull/13669#issuecomment-2378828778) for easier copy-n-paste. Most of the time: [__It doesn't__](https://github.com/apache/nuttx/pull/13575#issuecomment-2367182327).

- The LLM behaves as [__Multiple Personas__](https://github.com/apache/nuttx/pull/13629#issuecomment-2376156849)? (Some extremely chatty and naggy)

- Then again: The [__LLM is Free__](https://lupyuen.github.io/articles/llm#call-the-gemini-llm). And it doesn't depend on [__GitHub Runners__](https://lupyuen.github.io/articles/ci).

_What if Google starts charging for their LLM?_

We'll scrounge around and switch to another Free LLM. Yeah life gets tough for [__Open Source Maintainers__](https://explore.tidelift.com/2024-survey) sigh.

> ![50 km overnight hike will cause hallucinations](https://lupyuen.github.io/images/llm-hike.jpg)

# What's Next

And that's how we created our __PR Review Bot__ in One Week...

- We call the __GitHub API__ to fetch NuttX Pull Requests

- Append the PR Body to the __NuttX PR Requirements__

- Which becomes the __LLM Prompt__ that we send to __Gemini API__

- Our Bot posts the Gemini Response as a __PR Review Comment__

- Due to quirks in the Gemini API: We use __Emoji Reactions__ to limit the API Calls

- Though our LLM Bot was created by __Sheer Accident__

  (It wasn't meant to be an AI Project!)

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
