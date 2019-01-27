#!
javac @sources.list -encoding utf8 -d bin
cd bin
jar cvf ../lsh.jar .
cd ..
