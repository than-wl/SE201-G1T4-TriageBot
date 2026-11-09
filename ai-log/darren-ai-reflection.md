# AI Use Reflection: Darren

## What I learned about using these tools effectively

The biggest change in how I worked was splitting the job between two tools. I
used Claude in a chat to plan each step and write the prompt, and Claude Code to
carry it out, with a fixed rule that it only staged changes and I made every
commit. Writing the prompt forced me to decide what "done" meant before any code
existed: which files it could touch, that it made no paid model calls, and that
it never looked at the final test cases. I also learned to fix the judging rule
before measuring. For semantic retrieval we agreed in advance that it only had
to stay within the noise floor of one case in 96, so a small drop could not be
argued away afterwards. When a result did not make sense to me, such as why the
mutation test flips the right answer while Semgrep's alert stays the same, I
kept asking until I could explain it back myself before I accepted it.

## Where the tools were strong, and where they were weak

They were strong at the repetitive groundwork: frozen case sets, run manifests,
a replay command that re-scores saved runs for free, and keeping long documents
consistent with the numbers. They were weak in the places that looked finished.
An AI-written test synced our real vector store with a one-row fixture and wiped
it, which only showed up as a hang during a paid run. The output limit counted
the model's hidden reasoning, so an answer in the smoke test was cut off. The
first mutation test compared baselines from different script versions, and it
was a teammate, not the tool, who noticed. The relevance grades misled us too:
the setting with the best score also returned the most advice for the wrong
language. Drafts of our slides kept features we had already dropped and phrased
observations as if they were rules.

## What went wrong, and what I would do differently

I did not add the Assisted-by trailer to my commits in the final phase, so the
history alone understates how much of that work was AI-assisted. The log entries
cover those commits, but I would set up a commit template on the first day. I
would also read every test that touches real data before running it, and start
the experiments earlier. Running all of them in the last two days left little
room when something broke, and that is when most of the mistakes above happened.
