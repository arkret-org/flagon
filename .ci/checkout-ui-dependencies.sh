#!/usr/bin/env bash
# Fetch and verify the exact UI Git revisions selected by Cargo.lock.
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "$repo_dir/scripts/ui_dependencies.py"
