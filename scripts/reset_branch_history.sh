#!/bin/bash

# Copy the current branch to an orphaned branch
git checkout --orphan orphan_branch

# Add all files currently to the orphaned branch
git add -A

# Perform an initial commit message on the branch.
git commit -am "Initial Commit"

# Delete the master branch
git branch -D master

# Rename the orphaned branch to the master branch.
git branch -m master

# Force push to the repository.
git push -f origin master

# Do some housekeeping.
git gc --aggressive --prune=all
