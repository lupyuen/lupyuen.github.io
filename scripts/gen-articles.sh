#!/usr/bin/env bash
# Convert articles from Markdown to HTML

set -e  #  Exit when any command fails.
set -x  #  Echo all commands.

# Generate article
function generate_article() {
    local article=$1
    local html=articles/$article.html
    local tmp=$article.tmp

    # Generate the article header
    cat scripts/articles/$article-header.html \
        scripts/rustdoc-header.html \
        >article-rustdoc-header.html

    # Convert the article with rustdoc
    rustdoc \
        --output articles \
        --html-in-header article-rustdoc-header.html \
        --html-before-content \
        scripts/rustdoc-before.html \
        src/$article.md

    # Delete the article header
    rm article-rustdoc-header.html

    # Fix the rustdoc output to work with Prism.js code highlighting
    # Change...
    #   <pre class="...">...</pre>
    # To...
    #   <pre class="..."><code>...</code></pre>
    # Change...
    #   <code><code>...</code></code>
    # To...
    #   <code>...</code>
    cp  $html $tmp
    cat $tmp \
        | sed 's/<pre class="\(.*\)">/<pre class="\1"><code>/' \
        | sed 's/<\/pre>/<\/code><\/pre>/' \
        | sed 's/<code><code>/<code>/' \
        | sed 's/<\/code><\/code>/<\/code>/' \
        >$html
    rm $tmp
}

# Generate an article
# generate_article rust

# Generate all articles in src
for f in src/*.md
do
    echo $f
    filename=$(basename -- "$f")
    # extension="${filename##*.}"
    filename="${filename%.*}"
    generate_article $filename
done
