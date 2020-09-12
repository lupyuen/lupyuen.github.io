#!/usr/bin/env bash
# Generate resume in HTML format

set -e  #  Exit when any command fails.
set -x  #  Echo all commands.

node node_modules/resume-cli export index.html --format html --theme stackoverflow 
