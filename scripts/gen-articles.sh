#!/usr/bin/env bash
# Convert articles from Markdown to HTML

set -e  #  Exit when any command fails.
set -x  #  Echo all commands.

# Generate article
function generate_article() {
    local article=$1

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
}

# Generate an article
# generate_article led

# Generate all articles in src
for f in src/*.md
do
    echo $f
    filename=$(basename -- "$f")
    # extension="${filename##*.}"
    filename="${filename%.*}"
    generate_article $filename
done
