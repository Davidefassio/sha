#ifndef SHA_224_HPP
#define SHA_224_HPP

#include <string>
#include <fstream>

// Hashing function
std::string sha_224(const std::string &, int);
std::string sha_224(std::ifstream &, int);

#endif /* SHA_224_HPP */
