# GitHub Contribution Troubleshooting

This guide helps when commits are visible in the repository but do not appear on your GitHub contribution graph.

## Check the Commit Email

GitHub matches contributions using the commit author email.

Check your latest commit locally:

```bash
git log -1 --format="%H%n%an%n%ae%n%ad%n%s"
```

For this repository, the latest pushed commit used:

```text
ThabetheMT
mzwandileT21@gmail.com
```

That exact email must exist on your GitHub account for the contribution to count.

## Make Sure the Email Is Verified

On GitHub:

1. Open `Settings`
2. Open `Emails`
3. Confirm the commit email is added
4. Confirm the email is verified

## Make Sure the Commit Qualifies

GitHub usually counts contributions when:

- the commit is pushed to the repository default branch
- or the commit reaches the default branch through a merged pull request

This repository uses `main`, so direct pushes to `main` should qualify once the email matches.

## Allow Time for Refresh

GitHub contribution graphs are not always instant. Wait a few minutes and refresh your profile.

## Fix Future Commits

If you want future commits to use a different email:

```bash
git config user.name "Your GitHub Name"
git config user.email "your_verified_github_email@example.com"
```

To set it globally for all repositories:

```bash
git config --global user.name "Your GitHub Name"
git config --global user.email "your_verified_github_email@example.com"
```

## If the Commit Was Already Pushed

If the email on an already-pushed commit is wrong, you have two common options:

- leave the existing commit as-is and fix your Git email for future commits
- rewrite the commit author and force-push, only if you are sure that is safe for the branch and collaborators

For a shared branch, the safer option is usually to fix future commits rather than rewrite history.
