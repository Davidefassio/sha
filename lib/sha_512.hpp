#ifndef SHA_512_HPP
#define SHA_512_HPP

#include <string>
#include <fstream>

// Hashing function
std::string sha_512(const std::string &, int);
std::string sha_512(std::ifstream &, int);

#endif /* SHA_512_HPP */
