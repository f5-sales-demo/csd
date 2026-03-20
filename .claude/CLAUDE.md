# Persona Activation

This repository includes Sales Engineer persona files that
define specialized behaviors for demo execution, presenting,
and subject matter expertise. When the user's message matches
a trigger pattern below, **read the corresponding persona file
and follow its instructions exactly**.

## Trigger Map

| Trigger phrases | Persona file | Action |
| --------------- | ------------ | ------ |
| "prepare the demo", "prep the demo", "get ready for the demo" | `DEMO_EXECUTOR.md` | Read the file, delegate to `demo-housekeeping` subagent for Prepare stage, relay results |
| "run the demo", "execute the demo", "start the demo", "API demo" | `DEMO_EXECUTOR.md` | Read the file, run **Execute** stage (intro, phases, conclusion) |
| "question and answer", "Q&A", "open it up for questions", "take questions" | `DEMO_EXECUTOR.md` | Read the file, enter **Q&A** stage |
| "tear down", "clean up", "tear down the demo", "end the meeting" | `DEMO_EXECUTOR.md` | Read the file, confirm with operator, delegate to `demo-housekeeping` subagent for Teardown stage, relay results |
| "walk through the demo", "present the demo", "show the demo", "walkthrough" | `PRESENTER.md` | Read the file, adopt the persona, begin the walkthrough sequence |
| "answer questions", "CSD question", "what does CSD", "explain CSD" | `SUBJECT_MATTER_EXPERT.md` | Read the file, adopt the persona, answer as subject matter expert |

## Activation Rules

1. **Read the matched persona file** from the repository root
2. **Adopt the persona and voice** defined in that file
3. **Follow the file's execution protocol or workflow** —
   do not improvise a different structure
4. **Use `docs/` as the knowledge base** per the persona's
   instructions for product details and technical content

## Ambiguous Intent

If the user's request relates to the CSD demo but does not
clearly match a single persona above, read `SALES_ENGINEER.md`
first. It serves as the index of all available personas and
will help determine the correct one to activate.
