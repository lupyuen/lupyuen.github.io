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
        | sed 's/lupyuen.github.io\"/lupyuen.codeberg.page\"/g' \
        | sed 's/lupyuen.github.io\/articles/lupyuen.codeberg.page\/articles/g' \
        | sed 's/lupyuen.github.io\/images/lupyuen.codeberg.page\/images/g' \
        | sed 's/lupyuen.github.io\/rss/lupyuen.codeberg.page\/rss/g' \
        | sed 's/github.com\/lupyuen\/lupyuen.github.io\/blob\/master\/images/codeberg.org\/lupyuen\/pages\/src\/branch\/main\/images/g' \
        >$html
    rm $tmp
}

# Sync the files in the current folder to $1
function sync_folder() {
    local sync=$1

    # Copy the files that may change
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

    # Rewrite lupyuen.github.io to lupyuen.codeberg.page in resume
    set +x  #  Disable Echo.
    cp index.html articles
    generate_article index
    cp articles/index.html .
    set -x  #  Echo all commands.

    # Rewrite lupyuen.github.io to lupyuen.codeberg.page in rss.xml
    set +x  #  Disable Echo.
    cp rss.xml articles/rss.html
    generate_article rss
    mv articles/rss.html rss.xml
    set -x  #  Echo all commands.

    # Testing: Rewrite lupyuen.github.io to lupyuen.codeberg.page
    # generate_article lte2 ; exit

    # Commit the modified files
    git status
    git add .
    git commit --all --message="Sync from lupyuen.github.io"
    git push

    # Return to the previous folder
    popd
}

# Update the current folder
git pull

# Sync to Codeberg Pages
sync_folder ../lupyuen.codeberg.page

# Sync to Codeberg Mirror roughly every 8th time
if [[ $(($RANDOM % 8)) == 0 ]]; then
    sync_folder ../codeberg.lupyuen.github.io
fi
