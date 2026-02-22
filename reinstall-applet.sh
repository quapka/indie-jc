#!/usr/bin/env bash

# TODO add proper command line interface
set -e

thresholdB=03
nPartiesB=03

if [ -n "$1" ]; then
    thresholdB="$(printf "%02X" $1)"
    nPartiesB="$(printf "%02X" $1)"
fi

if [ -n "$2" ]; then
    thresholdB="$(printf "%02X" $1)"
    nPartiesB="$(printf "%02X" $2)"
fi

params="$thresholdB$nPartiesB"
reader3="Gemalto PC Twin Reader 00 00"
reader4="Gemalto PC Twin Reader 01 00"
reader5="Alcor Link AK9563 02 00"

appletPath="./applet/build/javacard/indie.cap"

echo "Using $thresholdB-out-of-$nPartiesB setting"

./gradlew buildJavaCard -P build.cardType=JCOP4_P71 --rerun-tasks


gp --uninstall "$appletPath" --debug --reader "$reader3" || true
gp --uninstall "$appletPath" --debug --reader "$reader4" || true
gp --uninstall "$appletPath" --debug --reader "$reader5" || true

if (( "$nPartiesB" > 1 )); then
    gp --install "$appletPath" --params "$params" --debug --reader "$reader3"
    gp --install "$appletPath" --params "$params" --debug --reader "$reader4"
fi

if (( "$nPartiesB" == 3 )); then
    gp --install "$appletPath" --params "$params" --debug --reader "$reader5"
fi
