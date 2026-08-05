# Developer Workflow

Start each task from an updated `master` branch. Check out `master`, pull the
latest `origin/master` with fast-forward behavior, and create the task branch
from that updated commit.

Use one GitHub task for one branch and one pull request. Keep the work scoped to
that task. Do not include adjacent fixes, cleanup, alignment changes, or
validation findings unless the task explicitly asks for those changes.

Name task branches with the `feature/` prefix, the issue number, and the issue
title words in the same order. Use complete lowercase words separated by
hyphens.

Example for issue `#24`, `Document the developer workflow`:

```text
feature/issue-24-document-the-developer-workflow
```

Do not push directly to `master`. Push the task branch only.

Untracked or unapproved files must not be staged, committed, pushed, or used as
inputs for the task.

When asked to validate, validate only and report what is off. Do not make edits
from a validation request unless the task explicitly asks for edits.
