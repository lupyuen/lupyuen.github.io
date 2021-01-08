#!/usr/bin/env bash
# Convert articles from Markdown to HTML

# Article to be generated
article=led

set -e  #  Exit when any command fails.
set -x  #  Echo all commands.

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
