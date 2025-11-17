#!/usr/bin/env bash
set -e

showHelp() {
cat << EOF  
Usage: ./$0 [-hbr] [-- ...]
Test against a real physical JavaCard JCOP4

-h, --help                  Show help

--b, --build                Build a fresh version of the JavaCard

-r, --reader <index>        Index (0 or 1) of the JavaCard reader to use (default: 0)

[-- <args>]                 Additional arguments passed to Gradle test task

Examples:
./test_integration_jcardengine.sh --reader 2 -- --info --tests AppletTest.testSetup
EOF
}

# kudos to: https://stackoverflow.com/a/52674277
options=$(getopt --longoptions "help,build,reader:" --options "h,b,r:" --alternative -- "$@")
eval set -- "$options"

export readerIndex=0

while true
do
    case "$1" in
        -h|--help) 
            showHelp
            exit 0
            ;;
        -b|--build)
            export build=1
            ;;
        -r|--reader) 
            shift
            if test -n "$readerIndex"; then
                export readerIndex="$1"
            fi
            ;;
        --)
            shift
            break;;
    esac
shift
done

# Build the applet for the simulator
if test "$build" = "1"; then
    ./gradlew clean
    ./gradlew buildJavaCard \
        --rerun-tasks \
        -Pbuild.cardType=SIMULATOR
fi

# Start JCardEngine in the background
if test "$readerIndex" = "0"; then
    export vsmartcardPort=35963
elif test "$readerIndex" = "1"; then
    export vsmartcardPort=35964
fi

java \
    -jar ~/projects/JCardEngine/tool/target/jcard.jar \
    --vsmartcard ~/projects/indie-jc/applet/build/javacard/indie.cap \
    --vsmartcard-port "$vsmartcardPort" \
    &
JCardEngine_PID=$!
echo "Started JCardEngine with PID: $JCardEngine_PID"

# Run tests against the physical card
./gradlew \
    test \
    --rerun-tasks \
    -Ptest.cardType=PHYSICAL \
    -Ptest.ReaderIndex="$readerIndex" \
    $@

# Clean up
kill -9 $JCardEngine_PID
