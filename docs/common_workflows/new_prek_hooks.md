# 🪝 Adding new prek hooks

With PreK you can just go online and find any premade hook for anything that you want. Anything! You can look for linters and formatters in any language or security tools in any language, or you can even write your own hooks. It is very easy to modify, and you can automate anything. Here is a C++ linter, which I haven't added to the config, but you can if you want. It is just to show how easy it is to set up.
[https://github.com/cppcheck-opensource/cppcheck/blob/main/tools/git-pre-commit-cppcheck](https://github.com/cppcheck-opensource/cppcheck/blob/main/tools/git-pre-commit-cppcheck)

## Why Prek?

`Prek` was chosen as it is written in `Rust` and is much more efficient and performant than `pre-commit` while still maintaining all of the same functionality as `pre-commit` and being backwards compatible.
The elegance of `pre-commit` and `Prek` is its ease of use and minimal setup. There are a bunch of hooks, and all of them are isolated and completely self-contained; they require minimal configuration and accomplish a specific task.
Unlike the CI pipeline that I made for `JavaScript`, this one is completely independent of everything and can be easily modified and run within any environment and easily expanded upon to accomplish almost any task.

The following types of tools have been added using pre-commit:

- Security Tools
- Python Environment Tools
- Code Quality Tools
- File System Tools
- Git Tools (and Git Commit Quality)
- Test Tools

## How to add new prek hooks?

You can utilize your search engine of choice to look for `pre-commit` hooks. Then it is as easy as copy and pasting them into the `.pre-commit-config.yaml` file. Make sure to try and organize them by sections because there are a lot.

It is very easy to find a hook online that automates or completes a task that you need done.

The configuration for `prek` is `prek.toml`. A generic hook looks something like:

\[[repos]\]
repo = [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
rev = "v8.30.1"
hooks = \[
{
id = "gitleaks",
name = "🔒 security · Detect hardcoded secrets"
}
\]

The other configuration made for `pre-commit` is `.pre-commit-config.yaml`. A generic hook looks something like:

- repo: [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
  rev: v8.30.1
  hooks:
  - id: gitleaks
    name: "🔒 security · Detect hardcoded secrets"

This is just to show an example, the `prek` version is the only one currently in use.
You find a hook, add it, maybe add some configuration, and it just runs!!!!
There are many tools that will be mentioned in later documentation. It is good to document and list all of the ones added to keep track. `gitleaks` is a security tool that can check if you have any secrets within your repository.
