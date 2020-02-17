all: sha

sha: main.cpp lib/sha_1.cpp lib/sha_224.cpp lib/sha_256.cpp lib/sha_384.cpp lib/sha_512.cpp
	g++ main.cpp lib/sha_1.cpp lib/sha_224.cpp lib/sha_256.cpp lib/sha_384.cpp lib/sha_512.cpp -o sha
	clear
