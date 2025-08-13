#!/bin/sh
set -e

PGIT_CONFIG=../pgit.yaml
WWW_DIR=./pub
REPOS_DIR=./repos
INDEX_FILE="$WWW_DIR/index.html"

ok()  { printf "OK  %s\n" "$*"; }
wrn() { printf "WRN %s\n" "$*"; }
err() { printf "ERR %s\n" "$*" >&2; }

ok "Syncing repositories..."
mkdir -p "$REPOS_DIR" "$WWW_DIR"
yq -r '.repos[] | .clone-url + " " + .label' "$PGIT_CONFIG" |
while read -r url label; do
    dir="$REPOS_DIR/$label"
    if [ "$dir" = ".." ]; then
        continue
    fi
    if [ -d "$dir/.git" ]; then
        wrn "Updating: $label"
        (cd "$dir" && git pull --ff-only)
    else
        ok "Cloning: $label"
        git clone --depth=1 "$url" "$dir"
    fi
done

ok "Running pgit..."
go run ../pgit.go --config "$PGIT_CONFIG"

ok "Generating index.html..."
{
    printf '%s\n' '<!DOCTYPE html><meta charset="utf-8"><title>xplshn git</title>'
    printf '<style>
    body{font-family:sans-serif;max-width:700px;margin:auto;background:#fff;color:#000}
    h1{border-bottom:1px solid #ccc}
    a{color:#06c;text-decoration:none}
    a:hover{text-decoration:underline}
    ul{list-style:none;padding:0}
    li{margin:0.5em 0}
    p{margin:0;font-size:0.9em;color:#555}
    </style>'
    printf '<h1>git.xplshn.com.ar</h1><ul>'
    yq -r '.repos[] | .label + "|" + .desc' "$PGIT_CONFIG" |
    while IFS='|' read -r label desc; do
        printf '<li><a href="./%s/">%s</a><p>%s</p></li>\n' "$label" "$label" "$desc"
    done
    printf '</ul>'
} > "$INDEX_FILE"

ok "All done."
