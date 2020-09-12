#!/usr/bin/env bash
# Generate resume in PDF format

set -e  #  Exit when any command fails.
set -x  #  Echo all commands.

node node_modules/resume-cli export lupyuen.pdf --format pdf --theme stackoverflow 
