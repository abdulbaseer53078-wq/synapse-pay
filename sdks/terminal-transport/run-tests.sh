#!/bin/sh
# Builds the library for Java 8 / older Android, then runs the Step 16 chaos test and the Step 25 mesh test (JDK 17+). No dependencies.
set -e
cd "$(dirname "$0")"
rm -rf out
javac --release 8 -Xlint:all,-options -Werror -d out/main $(find src/main -name '*.java')
javac -Xlint:all -Werror -cp out/main -d out/test $(find src/test -name '*.java')
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) sep=";" ;; *) sep=":" ;; esac
java -cp "out/main${sep}out/test" com.synapsepay.terminal.transport.ChaosTest
java -cp "out/main${sep}out/test" com.synapsepay.terminal.transport.MeshTest
