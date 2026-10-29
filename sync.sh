#!/bin/sh
# Fetch, rebase the current branch onto its upstream, and push.
set -eu
git fetch --prune
# --autostash: others edit this tree concurrently; keep their uncommitted
# changes out of the rebase's way.
git rebase --autostash
git push
