# AI Use Reflection: Darren

## What I learned about using these tools effectively

When working with Claude Code, what helped most was writing the rules into the request before it started. I told it to work offline, to check every quote against the source, and to send a bad answer to human review and never mark it as a false positive. Because I had written those rules down, I knew what to look for when I checked the result. I also learned to say what the tool should leave alone. I told it not to commit anything and not to touch my teammates’ files, because I did not want to collide with their work. It also helped to check what the tool told me against the repo. Some figures I was given were out of date once the team pushed new results, so I pulled the latest code and looked again.

## Where the tools were strong, and where they were weak

The tool was good at turning a clear spec into working code and tests fast. The validator came with 32 tests, and one of them feeds in a made-up claim that the validator has to reject. Later Darren added to the file and it now has 41. It was also good at reading through the repo to check my slides against the recorded results. It was weaker at staying inside what I asked. It expanded the paragraph about my work in the README far beyond what I wanted, and I asked for that pull request to be closed. I also had to delete a branch and redo the work twice. And what it told me about the project was only as current as the code it had seen.

## What went wrong, and what I would do differently

The clearest mistake is in my own log. The commit that added the validator (“validation: reject unsupported triage evidence”, e7cea32) used AI help but was merged without the Assisted-by: line the team rules ask for. It was already merged, so I did not rewrite shared history. I wrote it up in my AI log instead and added the line to later commits. Next time I would set up a commit template at the start so the line is never forgotten. I would also pull the latest main before asking the tool for any changes, so I don’t have to redo branches. The validator only proves that a quoted line exists. It does not prove the reasoning is right. With more time I would add a check on the reasoning, or look through a sample of dismissed cases by hand.