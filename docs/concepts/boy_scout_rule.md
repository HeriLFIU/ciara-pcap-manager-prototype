# Boy Scout Rule

## Explanation

One issue I found with previous CI pipelines I made is that they verify the entire repo and generate reports based on the entire repository. If you have an existing repository with a lot of untested and unlinted code, then the CI pipeline will always fail. That is why I modified this CI pipeline to follow the boy scout rule. By default it will only run on staged files and files within your pull request itself, nothing outside of that. If you do not like this behavior, then I have kept the old GitHub workflow in an archive folder. The old workflow is called ci.allfiles.yml. It can replace the existing one within the .github/workflows folder, and it will then check and generate reports for the entire repository.

## How it was implemented?

Made it so that the pre existing GitHub Actions Workflow followed the "boy scout rule". The CI Pipeline will now only verify new changes within the repository unless explicitly told otherwise. It will only verify new changes within the repository so that it does not constantly fail in older repos with a lot of legacy code which has not been properly linted, formatted, and tested.
