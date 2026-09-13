#!/usr/bin/env bash

# Reinstall applet on JavaCards with configurable threshold and party count
#
# Usage: ./reinstall-applet.sh [threshold] [nParties]
#
# Arguments:
#   threshold  - Required signatures for operations (default: 3)
#   nParties   - Total number of cards to use (default: auto-detect all cards)
#
# Examples:
#   ./reinstall-applet.sh           # 3-out-of-all-detected
#   ./reinstall-applet.sh 2         # 2-out-of-all-detected
#   ./reinstall-applet.sh 2 3       # 2-out-of-3 (installs on first 3 cards)
#   ./reinstall-applet.sh 3 5       # 3-out-of-5 (installs on first 5 cards)
#
# Note: If more cards are detected than nParties, only the first nParties
#       cards (lower index readers) will be used.

set -e

# Default values
threshold=3
nParties=0  # 0 means auto-detect

aggResult=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Parse command line arguments
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Reinstall applet on JavaCards with configurable threshold and party count"
    echo ""
    echo "Usage: $0 [threshold] [nParties]"
    echo ""
    echo "Arguments:"
    echo "  threshold  - Required signatures for operations (default: 3)"
    echo "  nParties   - Total number of cards to use (default: auto-detect all cards)"
    echo ""
    echo "Examples:"
    echo "  $0           # 3-out-of-all-detected"
    echo "  $0 2         # 2-out-of-all-detected"
    echo "  $0 2 3       # 2-out-of-3 (installs on first 3 cards)"
    echo "  $0 3 5       # 3-out-of-5 (installs on first 5 cards)"
    echo ""
    echo "Note: If more cards are detected than nParties, only the first nParties"
    echo "      cards (lower index readers) will be used."
    exit 0
fi

if [ -n "$1" ]; then
    threshold=$1
fi

if [ -n "$2" ]; then
    nParties=$2
fi


if ! gp --list > /dev/null 2>&1; then
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
else
    # there is likely only a single reader and it does not matter what is its name
    readersWithCard=("singleReaderNameDoesNotMatter")
fi

# Determine actual nParties to use
if [ $nParties -eq 0 ]; then
    # Auto-detect: use all detected cards
    nParties=${#readersWithCard[@]}
    echo "Auto-detected $nParties card(s)"
else
    echo "Using specified nParties=$nParties"
fi

# Validate we have enough cards
if [ ${#readersWithCard[@]} -lt $nParties ]; then
    echo "ERROR: Not enough cards detected. Need $nParties but only found ${#readersWithCard[@]}"
    exit 1
fi

# Only use the first nParties readers (lower index readers first)
readersToUse=("${readersWithCard[@]:0:$nParties}")

# Convert to hex for applet params
thresholdB="$(printf "%02X" $threshold)"
nPartiesB="$(printf "%02X" $nParties)"

# Validate threshold
if (( $threshold > $nParties )); then
    echo "ERROR: The threshold '$threshold' is greater than the number of parties '$nParties'"
    exit 1
fi

appletPath="./applet/build/javacard/indie.cap"

echo "Using $threshold-out-of-$nParties setting (threshold=$thresholdB, nParties=$nPartiesB)"
echo "Installing on ${#readersToUse[@]} card(s)"

./gradlew buildJavaCard -P build.cardType=JCOP4_P71 --rerun-tasks


echo "Greedy uninstalling old applet from selected cards"
for reader in "${readersToUse[@]}";
do
    echo "  Uninstalling from reader: $reader"
    gp --uninstall "$appletPath" --debug --reader "$reader" || true
done

params="$thresholdB$nPartiesB"
echo "Installing new applet on selected cards"
for reader in "${readersToUse[@]}";
do
    echo "  Installing on reader: $reader"
    gp --install "$appletPath" --params "$params" --debug --reader "$reader" || aggResult=$(( $? | $aggResult ))
done

echo ""
echo "========================================"
if test $aggResult -ne 0; then
    printf "${RED}FAILED${NC}: some installations failed\n"
    exit 1
else
    printf "${GREEN}PASSED${NC}: all installations passed\n"
    echo "Configuration: $threshold-out-of-$nParties"
    echo "Installed on ${#readersToUse[@]} card(s)"
fi
echo "========================================"
