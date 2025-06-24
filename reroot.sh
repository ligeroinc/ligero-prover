#!/usr/bin/env bash
# 1. Save the metadata from current HEAD
COMMIT_MSG=$(git log -1 --format=%B)
AUTHOR=$(git log -1 --format="%an <%ae>")
AUTHOR_DATE=$(git log -1 --format=%aD)
COMMITTER_DATE=$(git log -1 --format=%cD)

# 2. Create orphan branch
git checkout --orphan new-root

# 3. Stage all files
git add -A

# 4. Create commit with preserved metadata
GIT_COMMITTER_DATE="$COMMITTER_DATE" git commit \
  --author="$AUTHOR" \
  --date="$AUTHOR_DATE" \
  -m "$COMMIT_MSG"

# 5. Tag it
git tag v1.0.0

# 6. Replace main branch
git branch -D main
git branch -m main

# 7. Force push
#git push origin main --force --tags
