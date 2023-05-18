#!/usr/bin/env bash
# Sync from lupyuen.github.io to lupyuen.codeberg.pages

set -e  #  Exit when any command fails.
set -x  #  Echo all commands.

# Rewrite lupyuen.github.io to lupyuen.codeberg.page in articles/$1.html
function generate_article() {
    local article=$1
    local html=articles/$article.html
    local tmp=$article.tmp

    cp  $html $tmp
    cat $tmp \
        | sed 's/lupyuen.github.io\/images/lupyuen.codeberg.page\/images/' \
        | sed 's/lupyuen.github.io\/articles/lupyuen.codeberg.page\/articles/' \
        >$html
    rm $tmp
}

# Update the current folder
git pull

# Sync to this folder
sync=../lupyuen.codeberg.page

# Copy the modified files
set +x  #  Disable Echo.
cp *.* $sync/
cp .gitattributes $sync/
cp .gitignore $sync/
cp .vscode/* $sync/.vscode/
cp articles/* $sync/articles/
cp images/*.* $sync/images/
cp scripts/*.* $sync/scripts/
cp scripts/articles/* $sync/scripts/articles/
cp src/* $sync/src/
set -x  #  Echo all commands.

# Go to the sync folder
pushd $sync

# Testing: Rewrite lupyuen.github.io to lupyuen.codeberg.page
# generate_article lte2 ; exit

# Rewrite lupyuen.github.io to lupyuen.codeberg.page in articles/*.html
set +x  #  Disable Echo.
for f in src/*.md
do
    # echo $f
    filename=$(basename -- "$f")
    # extension="${filename##*.}"
    filename="${filename%.*}"
    generate_article $filename
done
set -x  #  Echo all commands.

# Commit the modified files
git status
git add .
git commit --all --message="Sync from lupyuen.github.io"
git push

# Return to the previous folder
popd
