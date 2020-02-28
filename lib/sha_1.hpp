#ifndef SHA_1_HPP
#define SHA_1_HPP

#include <string>
#include <fstream>

// Hashing function
std::string sha_1(const std::string &);
std::string sha_1(std::ifstream &);

#endif /* SHA_1_HPP */
