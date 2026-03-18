#!/bin/sh
set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
git config core.hooksPath "$REPO_ROOT/.githooks"
echo "Git hooks installed from .githooks/"
