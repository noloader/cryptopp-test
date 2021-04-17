The ZIP was downloaded from https://seed.kisa.or.kr/kisa/Board/22/detailView.do.

Once downloaded, unzip and then run make. Running make populates source/c/no_arch/src with LSH source files from the distribution.

After the source files are populated, cd into source/c/no_arch/src. We added the following programs, which use the LSH reference implementation:

  * Makefile
  * gen_lsh256.cpp
  * gen_lsh512.cpp

Once the two gen programs are built, they will generate test vectors using the reference implementation. The format is suitable to drop in cryptopp/TestVectors. Something like:

  ./gen_lsh256.exe > ~/cryptopp/TestVectors/lsh256.txt
  ./gen_lsh512.exe > ~/cryptopp/TestVectors/lsh512.txt
