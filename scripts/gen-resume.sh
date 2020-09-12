#!/usr/bin/env bash
# Generate resume in HTML, PDF and RSS formats

set -e  #  Exit when any command fails.
set -x  #  Echo all commands.

# Generate HTML and PDF
scripts/gen-resume-html.sh
scripts/gen-resume-pdf.sh

# Fix HTML formatting by expanding all sections:
# Change
#   class="toggle-item" />
# To
#   class="toggle-item" checked="checked" />
cat index.html \
    | sed 's/class="toggle-item" \/>/class="toggle-item" checked="checked" \/>/' \
    >index2.html
cp index2.html index.html
rm index2.html

# Generate RSS feed
pushd json-to-rss
cargo run >../rss.xml
popd
