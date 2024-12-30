#!/usr/bin/env bash
# Sync from lupyuen.github.io to lupyuen.codeberg.pages

set -e  #  Exit when any command fails.
set -x  #  Echo all commands.

# Rewrite lupyuen.github.io to lupyuen.org or lupyuen.codeberg.page in articles/$1.html
function generate_article() {
    local article=$1
    local html=articles/$article.html
    local tmp=$article.tmp

    cp  $html $tmp
    if [[ "$PWD" == *"lupyuen.org"* ]]; then
      # Rewrite to lupyuen.org
      cat $tmp \
          | sed 's/lupyuen.github.io\"/lupyuen.org\"/g' \
          | sed 's/lupyuen.github.io\/articles/lupyuen.org\/articles/g' \
          | sed 's/lupyuen.github.io\/images/lupyuen.org\/images/g' \
          | sed 's/lupyuen.github.io\/rss/lupyuen.org\/rss/g' \
          | sed 's/lupyuen.github.io\/sitemap/lupyuen.org\/sitemap/g' \
          | sed 's/lupyuen.github.io\/<\/loc>/lupyuen.org\/<\/loc>/g' \
          | sed 's/github.com\/lupyuen\/lupyuen.github.io\/blob\/master\/images/codeberg.org\/lupyuen\/pages\/src\/branch\/main\/images/g' \
          >$html
    else
      # Rewrite to lupyuen.codeberg.page
      cat $tmp \
          | sed 's/lupyuen.github.io\"/lupyuen.codeberg.page\"/g' \
          | sed 's/lupyuen.github.io\/articles/lupyuen.codeberg.page\/articles/g' \
          | sed 's/lupyuen.github.io\/images/lupyuen.codeberg.page\/images/g' \
          | sed 's/lupyuen.github.io\/rss/lupyuen.codeberg.page\/rss/g' \
          | sed 's/lupyuen.github.io\/sitemap/lupyuen.codeberg.page\/sitemap/g' \
          | sed 's/lupyuen.github.io\/<\/loc>/lupyuen.codeberg.page\/<\/loc>/g' \
          | sed 's/github.com\/lupyuen\/lupyuen.github.io\/blob\/master\/images/codeberg.org\/lupyuen\/pages\/src\/branch\/main\/images/g' \
          >$html
    fi
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

    # Rewrite lupyuen.github.io in articles/*.html
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

    # Rewrite lupyuen.github.io in resume
    set +x  #  Disable Echo.
    cp index.html articles
    generate_article index
    cp articles/index.html .
    set -x  #  Echo all commands.

    # Rewrite lupyuen.github.io in RSS Feed
    set +x  #  Disable Echo.
    cp rss.xml articles/rss.html
    generate_article rss
    mv articles/rss.html rss.xml
    set -x  #  Echo all commands.

    # Rewrite lupyuen.github.io in robots.txt
    set +x  #  Disable Echo.
    cp robots.txt articles/robots.txt.html
    generate_article robots.txt
    mv articles/robots.txt.html robots.txt
    set -x  #  Echo all commands.

    # Rewrite lupyuen.github.io in Sitemap
    set +x  #  Disable Echo.
    cp sitemap.xml articles/sitemap.xml.html
    generate_article sitemap.xml
    mv articles/sitemap.xml.html sitemap.xml
    set -x  #  Echo all commands.

    # Testing: Rewrite lupyuen.github.io
    # generate_article lte2 ; exit

    # Commit the modified files to Docker or lupyuen.codeberg.page
    if [[ "$sync" == *"lupyuen.org" ]]; then
      local src=$HOME/lupyuen.org
      local dest=lupyuen:/usr/local/apache2/htdocs
      set +x  #  Disable Echo.
      for filename in $src/*; do
        docker cp $filename $dest
      done
      set -x  #  Echo all commands.
    else
      git pull
      git status
      git add .
      git commit --all --message="Sync from lupyuen.github.io"
      git push
    fi

    # Return to the previous folder
    popd
}

# Update the current folder
git pull

# Sync to lupyuen.org
sync_folder ../lupyuen.org

# Sync to Codeberg Pages
sync_folder ../lupyuen.codeberg.page

# Sync to Codeberg Mirror roughly every 8th time
if [[ $(($RANDOM % 8)) == 0 ]]; then
    sync_folder ../codeberg.lupyuen.github.io
fi

exit

## Setup for lupyuen.org
## Based on https://hub.docker.com/_/httpd
docker run \
  -dit \
  --name lupyuen \
  -p 3003:80 \
  -v "$PWD":/usr/local/apache2/htdocs/ \
  httpd:2.4-alpine
docker restart lupyuen

## Copy HTTPD Config. Redirect /articles/ci7 to https://lupyuen.org/articles/ci7.html
## <IfModule alias_module>
##     RedirectMatch /articles/([^.]+)$ https://lupyuen.org/articles/$1.html
## <IfModule log_config_module>
##     CustomLog "logs/access_log" combined
## ErrorLog "logs/error_log"
## LoadModule remoteip_module modules/mod_remoteip.so
## RemoteIPHeader X-Forwarded-For
docker cp \
  lupyuen:/usr/local/apache2/conf/httpd.conf \
  .
docker cp \
  httpd.conf \
  lupyuen:/usr/local/apache2/conf/httpd.conf

## List HTML Files
docker exec \
  lupyuen \
  ls -la /usr/local/apache2/htdocs

## Copy HTML Files
src=$HOME/lupyuen.org
dest=lupyuen:/usr/local/apache2/htdocs
for filename in $src/*; do
  docker cp $filename $dest
done

## Show the logs
docker exec lupyuen tail -f logs/access_log
docker exec lupyuen tail -f logs/error_log
docker cp lupyuen:/usr/local/apache2/logs/access_log .

## Render the logs with GoAccess
## GeoLite2 Databse form http://dev.maxmind.com/geoip/geoip2/geolite2/
brew install goaccess
tar xvf GeoLite2-City_*.tar.gz
tar xvf GeoLite2-Country_*.tar.gz
cp GeoLite2-City_*/*.mmdb .
cp GeoLite2-Country_*/*.mmdb .
docker cp lupyuen:/usr/local/apache2/logs/access_log .
function run { for (( ;; )); do; goaccess access_log -o report.html --log-format=COMBINED --real-time-html --geoip-database=GeoLite2-City.mmdb ; date; sleep 10; done; } ; run &
open report.html
for (( ;; )); do; docker cp lupyuen:/usr/local/apache2/logs/access_log .; date; sleep 10; done;

## Update the Canonical Header
## <link rel="canonical" href="https://lupyuen.org/articles/TODO.html" />
## <!-- End scripts/articles/*-header.html -->
function update_header {
  local article=$1
  local file=$HOME/lupyuen.github.io/scripts/articles/$article-header.html
  local tmp_file=/tmp/canonical-header.html

  local search='<!-- End scripts'
  local replace='<link rel="canonical" href="https:\/\/lupyuen.org\/articles\/TODO.html" \/>\n<!-- End scripts'
  cat $file \
    | sed "s/$search/$replace/g" \
    >$tmp_file
  mv $tmp_file $file

  local search='TODO.html'
  local replace="$article.html"
  cat $file \
    | sed "s/$search/$replace/g" \
    >$tmp_file
  mv $tmp_file $file
}

for article in adc advocate arm auto auto2 bl706 blockly bme280 book boot cbor cbor2 chatgpt de de2 de3 debug display dsi dsi2 dsi3 expander fb flash gateway gpio grafana i2c ikea interrupt iot lcd led lisp loader lora lora2 lorawan lorawan2 lorawan3 lte lte2 lvgl lvgl2 lvgl3 lvgl4 mynewt nuttx openocd payload pinecone pinedio pinedio2 pinephone pinephone2 pio plic pr prometheus release rhai roblox rust rust2 rusti2c rustsim semihost sensor serial sourdough spi spi2 st7789 sx1262 terminal tflite tftp2 touch touch2 tsen ttn uart uboot unicorn unicorn2 usb usb2 usb3 visual wasm what wifi wisblock wisgate zig 
do
  echo article=$article
  update_header $article
done
