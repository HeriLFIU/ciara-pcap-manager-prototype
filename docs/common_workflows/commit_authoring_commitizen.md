# ✍️ Commit Authoring with Commitizen

We enforce **Conventional Commits** (types like `feat:`, `fix:`, `docs:`, etc.) so that our release tools can automatically bump versions and generate changelogs. We use [Commitizen](https://commitizen-tools.github.io/commitizen/) to interactively help create these structured commit messages.

## Day-to-Day Workflows

### The Interactive Commit Workflow

Instead of using `git commit -m "message"`, simply run:

```bash
cz commit
```

or just `git commit` if we have set up the commitizen Git hook (so `git commit` will launch the CZ wizard). This invokes Commitizen’s interactive CLI and guides you through crafting a properly formatted message.

#### The Wizard Steps

1. **Select type**: Choose the change type (e.g. `feat`, `fix`, `chore`, etc.) from the list.
1. **Scope (optional)**: Specify the section of the project affected (e.g. `api`, `parser`, or leave blank).
1. **Subject**: Write a brief, imperative summary (e.g. `add flow parsing function`).
1. **Body (optional)**: Provide more detail about the change if needed.
1. **Breaking changes**: If this commit introduces a breaking API change, indicate it here. (A “!” will be added after the type, and this will trigger a MAJOR version bump.)

Following these prompts produces a commit message like `feat(parser): add flow parsing function`, automatically conforming to our conventions. For more details, see Commitizen’s documentation.
