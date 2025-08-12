#!/bin/sh

set -ex

PGIT_CONFIG="../pgit.yaml"
WWW_DIR="./pub"
REPOS_DIR="./repos"
INDEX_FILE="$WWW_DIR/index.html"

echo "Syncing repositories..."
mkdir -p "$REPOS_DIR"
yq -r '.repos[] | .clone-url + " " + .label' "$PGIT_CONFIG" | while read -r url label; do
    path="$REPOS_DIR/$label"
    if [ -d "$path" ]; then
        echo "Updating: $label"
        (cd "$path" && git pull)
    else
        echo "Cloning: $label"
        git clone --depth=1 "$url" "$path"
    fi
done
echo "All repositories are up to date."
echo "---"


echo "Running pgit to generate repository sites..."
go run "../pgit.go" --config "$PGIT_CONFIG"
echo "pgit finished."
echo "---"


echo "Generating main index.html at $INDEX_FILE..."

cat > "$INDEX_FILE" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>xplshn git</title>
    <style>
        body {
            background-color: #282828;
            color: #ebdbb2;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 2em;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        h1 {
            color: #fe8019;
            border-bottom: 2px solid #504945;
            padding-bottom: 10px;
        }
        ul {
            list-style: none;
            padding: 0;
        }
        li {
            margin-bottom: 1.5em;
            background-color: #3c3836;
            padding: 15px;
            border-left: 5px solid #fe8019;
        }
        a {
            text-decoration: none;
            color: #83a598;
            font-weight: bold;
            font-size: 1.2em;
        }
        a:hover {
            color: #b8bb26;
        }
        p {
            margin: 5px 0 0;
            color: #bdae93;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>xplshn git Repositories</h1>
        <ul>
EOF

yq -r '.repos[] | .label + "|" + .desc' "$PGIT_CONFIG" | while IFS="|" read -r label desc; do
    cat >> "$INDEX_FILE" << EOF
            <li>
                <a href="./${label}/">${label}</a>
                <p>${desc}</p>
            </li>
EOF
done

cat >> "$INDEX_FILE" << EOF
        </ul>
    </div>
</body>
</html>
EOF

echo "---"
echo "All done. Main index.html has been created successfully."

