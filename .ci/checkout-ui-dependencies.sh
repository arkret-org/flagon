#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ui_dir="$(dirname "$(dirname "$repo_dir")")/glory-rs"
mkdir -p "$ui_dir"
checkout() {
    local name="$1" url="$2" revision="$3" destination="$ui_dir/$1"
    if [[ -e "$destination" ]]; then
        test -f "$destination/Cargo.toml" || { echo "Invalid UI dependency: $destination" >&2; exit 1; }
        echo "Reusing $destination at $(git -C "$destination" rev-parse HEAD)"
        return
    fi
    git clone --no-checkout "$url" "$destination"
    git -C "$destination" checkout --detach "$revision"
}
checkout glory https://github.com/glory-rs/glory.git 81cf630427a6b6c96951c315402b8565954e3d94
checkout sapid https://github.com/sapid-ui/sapid.git fd64d78edf9f91f9dc63bfa2be6e59ec1f739a58
