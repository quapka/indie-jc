#!/usr/bin/env bash
set -e

showHelp() {
cat << EOF  
Usage: ./$0 Usage: ./$0 [-hbir] [-- ...]
Test against a real physical JavaCard JCOP4

-h, --help                  Show help

--b, --build                Build a fresh version of the JavaCard, implies --install

-i, --install               Install the latest build onto the JavaCard before testing

-r, --reader <index>        Index of the JavaCard reader to use (default: 2)

[-- <args>]                 Additional arguments passed to Gradle test task

Examples:
./test_integration_jcardengine.sh --reader 2 -- --info --tests AppletTest.testSetup
EOF
}

# kudos to: https://stackoverflow.com/a/52674277
options=$(getopt --longoptions "help,build,install,reader:" --options "h,b,i,r:" --alternative -- "$@")
eval set -- "$options"

export readerIndex=2

while true
do
    case "$1" in
        -h|--help) 
            showHelp
            exit 0
            ;;
        -b|--build)
            export install=1
            export build=1
            ;;
        -r|--reader) 
            shift
            if test -n "$readerIndex"; then
                export readerIndex="$1"
            fi
            ;;
        -i|--install)
            export install=1
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
    ./gradlew buildJavaCard --rerun-tasks -Pbuild.cardType=JCOP4_P71
fi

# The uninstallation assumes that the AID is static across builds and can be used to uninstall even older CAP versions
if test "$install" = "1"; then
    gp --debug --uninstall applet/build/javacard/indie.cap || true
    gp --debug --install applet/build/javacard/indie.cap
fi

# Run tests against the physical card
./gradlew test --rerun-tasks -Ptest.cardType=PHYSICAL -Ptest.ReaderIndex="$readerIndex" $@
