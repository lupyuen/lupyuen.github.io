#!/usr/bin/env bash
# Sync from lupyuen.org to lupyuen.codeberg.pages

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
    if [[ "$sync" == "../lupyuen.org" ]]; then
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
      git commit --all --message="$commit_msg"
      git push
    fi

    # Return to the previous folder
    popd
}

# Update the current folder and fetch the Commit Title
commit_msg=$(git --no-pager log -1 --format="%s")
git pull

# Sync to lupyuen.org
sync_folder ../lupyuen.org

# Sync to Codeberg Pages
sync_folder ../lupyuen.codeberg.page

# Sync to Codeberg Mirror roughly every 8th time
if [[ $(($RANDOM % 8)) == 0 ]]; then
    sync_folder ../codeberg.lupyuen.org
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
docker update --restart always lupyuen
docker restart lupyuen

## Copy HTTPD Config. Redirect /articles/ci7 to https://lupyuen.org/articles/ci7.html
## <IfModule alias_module>
##     RedirectMatch permanent /articles/([^.]+)$ https://lupyuen.org/articles/$1.html
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
## Somehow GoAccess needs to be restarted once in a while
for (( ; ; )); do ; pkill -9 goaccess ; date ; sleep 60 ; done

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

## grep -L canonical $HOME/lupyuen.github.io/scripts/articles/*.html
for article in adc advocate arm auto auto2 bl706 blockly bme280 book boot cbor cbor2 chatgpt de de2 de3 debug display dsi dsi2 dsi3 expander fb flash gateway gpio grafana i2c ikea interrupt iot lcd led lisp loader lora lora2 lorawan lorawan2 lorawan3 lte lte2 lvgl lvgl2 lvgl3 lvgl4 mynewt nuttx openocd payload pinecone pinedio pinedio2 pinephone pinephone2 pio plic pr prometheus release rhai roblox rust rust2 rusti2c rustsim semihost sensor serial sourdough spi spi2 st7789 sx1262 terminal tflite tftp2 touch touch2 tsen ttn uart uboot unicorn unicorn2 usb usb2 usb3 visual wasm what wifi wisblock wisgate zig 
do
  echo article=$article
  update_header $article
done

## Update the Canonical Header for Legacy Articles
##   <link rel="canonical" href="https://lupyuen.org/articles/TODO.html" />
##   <!-- End Wayback Rewrite JS Include -->
function update_header2 {
  local article=$1
  local file=$HOME/lupyuen.github.io/articles/$article.html
  local tmp_file=/tmp/canonical-header.html

  local search='<!-- End Wayback'
  local replace='<link rel="canonical" href="https:\/\/lupyuen.org\/articles\/TODO.html" \/>\n  <!-- End Wayback'
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

## grep -L canonical $HOME/lupyuen.github.io/articles/*.html
for article in advanced-topics-for-visual-embedded-rust-programming bluetooth-mesh-with-nrf52-and-apache-mynewt build-an-nb-iot-gps-tracker-on-stm32-l476-with-apache-mynewt-and-embedded-rust build-and-flash-rust-mynewt-firmware-for-pinetime-smart-watch build-your-iot-sensor-network-stm32-blue-pill-nrf24l01-esp8266-apache-mynewt-thethings-io building-a-rust-driver-for-pinetimes-touch-controller coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code connect-stm32-blue-pill-to-esp8266-with-apache-mynewt connect-stm32-blue-pill-to-nb-iot-with-quectel-bc95-g-and-apache-mynewt connect-the-nb-iot-hardware-stm32-blue-pill-and-quectel-bc95-g-module create-your-iot-gadget-with-apache-mynewt-and-stm32-blue-pill debug-rust-mynewt-firmware-for-pinetime-on-raspberry-pi get-started-with-nb-iot-and-quectel-modules hey-gd32-vf103-on-risc-v-i-surrender-for-now hosting-embedded-rust-apps-on-apache-mynewt-with-stm32-blue-pill install-apache-mynewt-and-embedded-rust-for-nrf52-and-visual-studio-code-on-windows-and-macos install-apache-mynewt-and-embedded-rust-for-stm32-l476-and-visual-studio-code-on-windows install-apache-mynewt-on-windows install-bluetooth-mesh-and-apache-mynewt-for-nrf52-and-visual-studio-code-on-windows-and-macos install-embedded-rust-and-apache-mynewt-for-visual-studio-code-on-windows install-low-power-apache-mynewt-and-embedded-rust-for-visual-studio-code-on-windows install-meshctl-on-raspberry-pi low-power-nb-iot-on-stm32-blue-pill-with-apache-mynewt-and-embedded-rust my-5-year-iot-mission my-first-week-as-embedded-foss-advocate nuttx3 openocd-on-raspberry-pi-better-with-swd-on-spi optimising-pinetimes-display-driver-with-rust-and-mynewt porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v porting-druid-rust-widgets-to-pinetime-smart-watch quick-peek-of-huawei-liteos-with-nb-iot-on-ghostyu-nb-ek-l476-developer-kit rust-rocks-nb-iot-stm32-blue-pill-with-quectel-bc95-g-on-apache-mynewt safer-simpler-embedded-rust-with-apache-mynewt-on-stm32-blue-pill sneak-peek-of-pinetime-smart-watch-and-why-its-perfect-for-teaching-iot stm32-blue-pill-analyse-and-optimise-your-ram-and-rom stm32-blue-pill-bootloading-the-webusb-bootloader stm32-blue-pill-dissecting-the-webusb-bootloader-for-makecode stm32-blue-pill-shrink-your-math-libraries-with-qfplib stm32-blue-pill-unit-testing-with-qemu-blue-pill-emulator stm32-blue-pill-usb-bootloader-how-i-fixed-the-usb-storage-serial-dfu-and-webusb-interfaces super-blue-pill-like-stm32-blue-pill-but-better visual-embedded-rust-programming-with-visual-studio-code 
do
  echo article=$article
  update_header2 $article
done
