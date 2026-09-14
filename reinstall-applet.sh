#!/usr/bin/env bash

# Reinstall applet on JavaCards with configurable threshold and party count
#
# Usage: ./reinstall-applet.sh [threshold] [nParties] [numInstalls]
#
# Arguments:
#   threshold    - Required signatures for operations (default: 3)
#   nParties     - Total number of cards to use (default: auto-detect all cards)
#   numInstalls  - Number of times to reinstall (default: 1, for benchmarking)
#
# Examples:
#   ./reinstall-applet.sh           # 3-out-of-all-detected, single install
#   ./reinstall-applet.sh 2         # 2-out-of-all-detected, single install
#   ./reinstall-applet.sh 2 3       # 2-out-of-3 (installs on first 3 cards), single install
#   ./reinstall-applet.sh 3 5       # 3-out-of-5 (installs on first 5 cards), single install
#   ./reinstall-applet.sh 2 3 5     # 2-out-of-3, repeat installation 5 times
#
# Note: If more cards are detected than nParties, only the first nParties
#       cards (lower index readers) will be used.

set -e

# Default values
threshold=3
nParties=0  # 0 means auto-detect
numInstalls=1

aggResult=0
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse command line arguments
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Reinstall applet on JavaCards with configurable threshold and party count"
    echo ""
    echo "Usage: $0 [threshold] [nParties] [numInstalls]"
    echo ""
    echo "Arguments:"
    echo "  threshold    - Required signatures for operations (default: 3)"
    echo "  nParties     - Total number of cards to use (default: auto-detect all cards)"
    echo "  numInstalls  - Number of times to reinstall (default: 1, for benchmarking)"
    echo ""
    echo "Examples:"
    echo "  $0           # 3-out-of-all-detected, single install"
    echo "  $0 2         # 2-out-of-all-detected, single install"
    echo "  $0 2 3       # 2-out-of-3 (installs on first 3 cards), single install"
    echo "  $0 3 5       # 3-out-of-5 (installs on first 5 cards), single install"
    echo "  $0 2 3 5     # 2-out-of-3, repeat installation 5 times"
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

if [ -n "$3" ]; then
    numInstalls=$3
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
echo "Number of installation iterations: $numInstalls"

./gradlew buildJavaCard -P build.cardType=JCOP4_P71 --rerun-tasks

# Arrays to store timing results
declare -a installTimes

# CSV output file
csvFile="applet/benchmark_results/installation_results.csv"
timestamp=$(date -Iseconds)

# Generate UUID for this measurement session
sessionUUID=$(uuidgen)

# Create directory if it doesn't exist
mkdir -p "applet/benchmark_results"

# Write CSV header if file doesn't exist
if [ ! -f "$csvFile" ]; then
    echo "timestamp,session_uuid,threshold,nParties,card_index,reader_name,duration_ms,session_iteration" > "$csvFile"
fi

# Installation loop
for (( iteration=1; iteration<=numInstalls; iteration++ )); do
    aggResult=0

    if [ $numInstalls -gt 1 ]; then
        echo ""
        printf "${BLUE}=== Installation iteration $iteration/$numInstalls ===${NC}\n"
    fi

    echo "Greedy uninstalling old applet from selected cards"
    for reader in "${readersToUse[@]}";
    do
        echo "  Uninstalling from reader: $reader"
        gp --uninstall "$appletPath" --debug --reader "$reader" || true
    done

    params="$thresholdB$nPartiesB"
    echo "Installing new applet on selected cards"

    # Install on each card and time individually
    cardIndex=0
    for reader in "${readersToUse[@]}";
    do
        echo "  Installing on reader: $reader"

        # Time this individual card installation
        cardInstallStart=$(date +%s%N)
        gp --install "$appletPath" --params "$params" --debug --reader "$reader" || aggResult=$(( $? | $aggResult ))
        cardInstallEnd=$(date +%s%N)

        cardInstallDuration=$(( (cardInstallEnd - cardInstallStart) / 1000000 ))  # Convert to milliseconds
        installTimes+=($cardInstallDuration)

        # Write per-card timing to CSV
        echo "$timestamp,$sessionUUID,$threshold,$nParties,$cardIndex,\"$reader\",$cardInstallDuration,$iteration" >> "$csvFile"

        if [ $numInstalls -gt 1 ]; then
            printf "${BLUE}    Card $cardIndex installation time: ${cardInstallDuration} ms${NC}\n"
        fi

        cardIndex=$((cardIndex + 1))
    done

    if test $aggResult -ne 0; then
        printf "${RED}FAILED${NC}: some installations failed in iteration $iteration\n"
        exit 1
    fi
done

echo ""
echo "========================================"
printf "${GREEN}PASSED${NC}: all installations passed\n"
echo "Configuration: $threshold-out-of-$nParties"
echo "Installed on ${#readersToUse[@]} card(s)"
echo "Session UUID: $sessionUUID"
echo "Results saved to: $csvFile"

# Print timing statistics if multiple installations
if [ $numInstalls -gt 1 ]; then
    echo ""
    echo "Installation timing results:"
    echo "  Iterations: $numInstalls"
    echo "  Cards per iteration: ${#readersToUse[@]}"

    totalMeasurements=${#installTimes[@]}
    echo "  Total measurements: $totalMeasurements"

    # Calculate overall statistics
    sum=0
    for time in "${installTimes[@]}"; do
        sum=$((sum + time))
    done
    mean=$((sum / totalMeasurements))

    # Calculate standard deviation
    variance=0
    for time in "${installTimes[@]}"; do
        diff=$((time - mean))
        variance=$((variance + diff * diff))
    done
    stddev=$(echo "scale=2; sqrt($variance / $totalMeasurements)" | bc)

    # Find min and max
    min=${installTimes[0]}
    max=${installTimes[0]}
    for time in "${installTimes[@]}"; do
        [ $time -lt $min ] && min=$time
        [ $time -gt $max ] && max=$time
    done

    echo "  Overall Mean: $mean ms"
    echo "  Overall Std Dev: $stddev ms"
    echo "  Min: $min ms"
    echo "  Max: $max ms"

    # Per-card statistics if multiple cards
    if [ ${#readersToUse[@]} -gt 1 ]; then
        echo ""
        echo "  Per-card statistics:"
        for (( cardIdx=0; cardIdx<${#readersToUse[@]}; cardIdx++ )); do
            # Extract times for this card (every Nth element starting at cardIdx)
            cardTimes=()
            for (( i=cardIdx; i<totalMeasurements; i+=${#readersToUse[@]} )); do
                cardTimes+=("${installTimes[$i]}")
            done

            # Calculate mean for this card
            cardSum=0
            for time in "${cardTimes[@]}"; do
                cardSum=$((cardSum + time))
            done
            cardMean=$((cardSum / ${#cardTimes[@]}))

            echo "    Card $cardIdx (${readersToUse[$cardIdx]}): Mean=$cardMean ms (n=${#cardTimes[@]})"
        done
    fi
fi

echo "========================================"
