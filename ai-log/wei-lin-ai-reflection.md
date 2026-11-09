# AI Use Reflection: Darren

## What I learned about using these tools effectively

AI coding tools (OpenAI Codex and Claude Code) worked best when I gave them a narrow, clearly defined task and then checked the result myself. Vague requests like "make it better" produced changes that were hard to judge, while specific ones like "fix why this command-injection case was missed, without hard-coding the case, and add a test" produced something I could verify. I also learned to fix the rules before seeing the results: we froze the test cases and agreed in advance what counted as an improvement, so neither I nor the AI could tune things after the fact. Finally, I learned to explicitly ask the tool to be honest and challenge my ideas, because by default it tends to agree with me.

## Where the tools were strong, and where they were weak

Where were the tools strong, and where were they weak?
They were strong at the heavy lifting: writing code and tests quickly, tracing a bug across several files, running experiments consistently, and explaining technical results in simple terms. They were weak at judgement. They sometimes stated numbers or conclusions confidently that turned out to be loose or wrong when I asked them to recheck, and their information went out of date once teammates changed the code. Inside TriageBot itself, the model sometimes produced convincing but wrong arguments, for example deciding a real path-traversal bug was safe based on an incomplete argument. That is why every result had to be checked against the answer key and the source code rather than trusted.

## What went wrong, and what I would do differently

What went wrong, and what would you do differently?
Some of our improvements were built on very little evidence. The reasoning worksheet was motivated by contradictions we had seen, but it was tested on only five cases before we built it in, and the larger test showed no benefit. Semantic retrieval was set aside early partly because it was judged on AI-generated grades with no human review, yet it later turned out to work once its inputs were fixed. Next time I would run a small, cheap pilot before fully building a feature, have a person review any evaluation an AI produced, and coordinate branches more closely with my teammates so we were not working from out-of-date assumptions.

(Written by Wei Lin, committed by Darren on behalf of Wei Lin)