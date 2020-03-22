#ifndef SHA_384_HPP
#define SHA_384_HPP

#include <string>
#include <fstream>

// Hashing function
std::string sha_384(const std::string &, int);
std::string sha_384(std::ifstream &, int);

#endif /* SHA_384_HPP */
