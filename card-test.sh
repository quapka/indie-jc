#!/usr/bin/env bash
gp --uninstall applet/build/javacard/indie.cap
./gradlew buildJavaCard
./gradlew installJavaCard

if [ -z "$1" ]; then
    ./gradlew test --rerun-tasks --info
else 
    ./gradlew test --rerun-tasks --info --tests "$1"
fi
