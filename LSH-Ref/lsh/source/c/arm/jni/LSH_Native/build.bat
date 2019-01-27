@echo off
javac -source 1.6 -target 1.6 @sources.list -encoding utf8 -d bin
cd bin
jar cvf ../LshNative.jar .
cd ..
@echo on