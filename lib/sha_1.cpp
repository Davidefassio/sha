#include <cstdint>
#include <sstream>
#include <iomanip>
#include <iostream>
#include "sha_1.hpp"

// Leftrotate a 32bit number
uint32_t rol(uint32_t value, size_t bits){
    return (value << bits) | (value >> (32 - bits));
}

// Hash a single 512-bit block. This is the core of the algorithm
void transform(uint32_t digest[5], uint32_t block[80], uint64_t &transforms){
    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];
    uint32_t f, temp;

    for(int i = 0; i < 80; i++){
        if(i < 20){
            f = (d ^ (b & (c ^ d))) + 0x5a827999;
        }
        else if(i < 40){
            f = (b ^ c ^ d) + 0x6ed9eba1;
        }
        else if(i < 60){
            f = ((b & c) | (d & (b | c))) + 0x8f1bbcdc;
        }
        else{
            f = (b ^ c ^ d) + 0xca62c1d6;
        }

        temp = rol(a, 5) + f + e + block[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;

    // Count the number of transformations
    transforms++;
}

// Convert a 512bits buffer into 80 32bits words
void buffer_to_block(std::string &buffer, uint32_t block[80]){
    for(size_t i = 0; i < 16; i++){
        block[i] = (buffer[4*i+3] & 0xff) | (buffer[4*i+2] & 0xff)<<8 | (buffer[4*i+1] & 0xff)<<16 | (buffer[4*i+0] & 0xff)<<24;
    }

    for(size_t i = 16; i < 80; i++){
        block[i] = rol(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
    }
}

// Hash function, input from a string
std::string sha_1(const std::string &s){
    // Variables declaration
    uint32_t digest[5];
    std::string buffer;
    uint64_t transforms = 0;

    // SHA1 initialization constants
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

    std::istringstream is(s);

    while(true){
        char sbuf[64];
        is.read(sbuf, 64);
        buffer.append(sbuf, (std::size_t) is.gcount());

    	if(buffer.size() != 64){
    	    break;
    	}

        uint32_t block[80];
        buffer_to_block(buffer, block);
        transform(digest, block, transforms);
        buffer.clear();
    }

    // Total number of hashed bits
    uint64_t total_bits = (transforms*64 + buffer.size()) * 8;

    // Padding
    buffer += (char) 0x80;
    size_t orig_size = buffer.size();
    while(buffer.size() < 64){
        buffer += (char) 0x00;
    }

    uint32_t block[80];
    buffer_to_block(buffer, block);

    if(orig_size > 56){
        transform(digest, block, transforms);
        for(size_t i = 0; i < 14; i++){
            block[i] = 0;
        }
    }

    // Append total_bits, split this uint64_t into two uint32_t
    block[14] = (uint32_t) (total_bits >> 32);
    block[15] = (uint32_t) total_bits;
    for(int i = 16; i < 80; i++){
        block[i] = rol(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
    }

    transform(digest, block, transforms);

    // Hex std::string
    std::ostringstream result;
    for(size_t i = 0; i < 5; i++){
        result << std::hex << std::setfill('0') << std::setw(8) << digest[i];
    }

    return result.str();
}

// Hash function, input from a file
std::string sha_1(std::ifstream &in){
    // Variables declaration
    uint32_t digest[5];
    std::string buffer;
    uint64_t transforms = 0;

    // SHA1 initialization constants
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

    while(true){
        char sbuf[64];
        in.read(sbuf, 64);

        size_t cnt = in.gcount();
        for(size_t i = 0; i < in.gcount(); i++){
            if(sbuf[i] == 10 && i == in.gcount() - 1 && in.gcount() != 64){
                sbuf[i] = (char) 0;
                cnt--;
            }
            else if(sbuf[i] == 10){
                sbuf[i] = (char) 32;
            }
        }

        buffer.append(sbuf, cnt);

    	if(buffer.size() != 64){
    	    break;
    	}

        uint32_t block[80];
        buffer_to_block(buffer, block);
        transform(digest, block, transforms);
        buffer.clear();
    }

    // Total number of hashed bits
    uint64_t total_bits = (transforms*64 + buffer.size()) * 8;

    // Padding
    buffer += (char) 0x80;
    size_t orig_size = buffer.size();
    while(buffer.size() < 64){
        buffer += (char) 0x00;
    }

    uint32_t block[80];
    buffer_to_block(buffer, block);

    if(orig_size > 56){
        transform(digest, block, transforms);
        for(size_t i = 0; i < 14; i++){
            block[i] = 0;
        }
    }

    // Append total_bits, split this uint64_t into two uint32_t
    block[14] = (uint32_t) (total_bits >> 32);
    block[15] = (uint32_t) total_bits;
    for(int i = 16; i < 80; i++){
        block[i] = rol(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
    }

    transform(digest, block, transforms);

    // Hex std::string
    std::ostringstream result;
    for(size_t i = 0; i < 5; i++){
        result << std::hex << std::setfill('0') << std::setw(8) << digest[i];
    }

    return result.str();
}
