@echo off

cd bin
javah kr.re.nsr.crypto.hash.LshNative
javah kr.re.nsr.crypto.mac.HmacLshNative

cd ..
move bin\*.h .