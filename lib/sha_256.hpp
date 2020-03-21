#ifndef SHA_256_HPP
#define SHA_256_HPP

#include <string>
#include <fstream>

// Hashing function
std::string sha_256(const std::string &, int);
std::string sha_256(std::ifstream &, int);

#endif /* SHA_256_HPP */
