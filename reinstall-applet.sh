#!/usr/bin/env bash

# TODO add proper command line interface
set -e

thresholdB=03
# nPartiesB=03

if [ -n "$1" ]; then
    thresholdB="$(printf "%02X" $1)"
    # nPartiesB="$(printf "%02X" $1)"
fi

if [ -n "$2" ]; then
    thresholdB="$(printf "%02X" $1)"
    # nPartiesB="$(printf "%02X" $2)"
fi

params="$thresholdB$nPartiesB"

# Iterate through available readers
availableReaders=()
mapfile -t availableReaders < \
    <( \
        gp --reader nonExistentReaderIndex 2>&1 \
        | grep '^-' \
        | sed -e 's/^- //'
    )
# Build an array of readers that have card inserted and working
readersWithCard=()
for reader in "${availableReaders[@]}";
do
    if gp --info --reader "$reader" > /dev/null 2>&1 ; then
        echo "Reader: '$reader' contains card"
        readersWithCard+=("$reader")
    fi
done

nPartiesB="$(printf "%02X" ${#readersWithCard[@]})"

appletPath="./applet/build/javacard/indie.cap"

echo "Using $thresholdB-out-of-$nPartiesB setting"

./gradlew buildJavaCard -P build.cardType=JCOP4_P71 --rerun-tasks


echo "Greedy uninstalling old applet"
for reader in "${readersWithCard[@]}";
do
    gp --uninstall "$appletPath" --debug --reader "$reader" || true
done

echo "Installing new applet"
for reader in "${readersWithCard[@]}";
do
    gp --install "$appletPath" --params "$params" --debug --reader "$reader"
done
