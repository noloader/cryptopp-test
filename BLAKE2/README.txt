These are modified source files that generate the test vectors. To use them:

    git clone https://github.com/BLAKE2/BLAKE2.git
    cd BLAKE2/ref
    cp .../cryptopp-test/BLAKE2/blake2s-ref.c .
    cp .../cryptopp-test/BLAKE2/blake2b-ref.c .
    make

And then, either:

    ./blake2s

or:

    ./blake2b

