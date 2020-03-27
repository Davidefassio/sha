/*
    MIT License

    Copyright (c) 2020 Davide Fassio

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include <cstdint>
#include <stdio.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include "../include/sha_256.hpp"

namespace sha256
{
    // Table of round constants
    static const uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    // Rightrotate a 32bit number (back rol)
    uint32_t b_rol(uint32_t value, size_t bits){
        return (value << (32 - bits) | (value >> bits));
    }

    // Hash a single 512-bit block. This is the core of the algorithm
    void transform(uint32_t digest[8], uint32_t block[64], uint64_t &transforms){
        uint32_t v[8], s0, s1, t1, t2, maj, ch;
        for(int i = 0; i < 8; i++){ v[i] = digest[i]; }

        for(int i = 0; i < 64; i++){
            s0 = sha256::b_rol(v[0], 2) ^ sha256::b_rol(v[0], 13) ^ sha256::b_rol(v[0], 22);
            maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            t2 = s0 + maj;

            s1 = sha256::b_rol(v[4], 6) ^ sha256::b_rol(v[4], 11) ^ sha256::b_rol(v[4], 25);
            ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
            t1 = v[7] + s1 + ch + sha256::k[i] + block[i];

            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3] + t1;
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1 + t2;
        }

        for(int i = 0; i < 8; i++){ digest[i] += v[i]; }

        // Count the number of transformations
        transforms++;
    }

    // Convert a 512bits buffer into 64 32bits words
    void buffer_to_block(std::string &buffer, uint32_t block[64]){
        for(size_t i = 0; i < 16; i++){
            block[i] = (buffer[4*i+3] & 0xff) | (buffer[4*i+2] & 0xff)<<8 | (buffer[4*i+1] & 0xff)<<16 | (buffer[4*i+0] & 0xff)<<24;
        }

        uint32_t s0, s1;
        for(size_t i = 16; i < 64; i++){
            s0 = sha256::b_rol(block[i-15], 7) ^ sha256::b_rol(block[i-15], 18) ^ (block[i-15] >> 3);
            s1 = sha256::b_rol(block[i-2], 17) ^ sha256::b_rol(block[i-2], 19) ^ (block[i-2] >> 10);
            block[i] = block[i-16] + s0 + block[i-7] + s1;
        }
    }
}

// Hash function, input from a string
std::string sha_256(const std::string &s, int mode){
    // Variables declaration
    uint32_t digest[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::string buffer;
    uint64_t transforms = 0;
    int min_len = 0;

    std::istringstream is(s);

    while(true){
        if(mode == 0){
            char sbuf[64];
            is.read(sbuf, 64);
            buffer.append(sbuf, (std::size_t) is.gcount());
        }
        else if(mode == 1){
            int tmp;
            char sbuf_e[128], sbuf[64];
            is.read(sbuf_e, 128);

            for(size_t i = 0; i < (std::size_t) (is.gcount() / 2); i++){
                std::stringstream ss;
                ss << sbuf_e[i*2];
                ss << sbuf_e[(i*2)+1];

                ss >> std::hex >>  tmp;
                sbuf[i] = (char) tmp;
            }

            if(is.gcount() % 2 != 0){
                std::stringstream ss;
                ss << sbuf_e[is.gcount() - 1];
                ss << (char) 0x30;

                ss >> std::hex >> tmp;
                sbuf[(is.gcount() - 1) / 2] = (char) (tmp | 0x08);

                buffer.append(sbuf, (std::size_t) ((is.gcount() + 1) / 2));
                min_len = 4;
            }
            else{
                buffer.append(sbuf, (std::size_t) is.gcount() / 2);
            }
        }
        else if(mode == 2){
            char sbuf_b[512], sbuf[64] = {0};
            is.read(sbuf_b, 512);

            for(size_t i = 0; i < is.gcount(); i++){
                if(sbuf_b[i] == '1'){
                    sbuf[(int) i / 8] |= (0x01 << (7 - (i%8)));
                }
            }

            if(is.gcount() % 8 == 0){
                buffer.append(sbuf, (std::size_t) is.gcount() / 8);
            }
            else{
                sbuf[is.gcount() / 8] |= ((0x01 << (7 - (is.gcount()%8))));
                buffer.append(sbuf, (std::size_t) ((is.gcount() / 8) + 1));
                min_len = 8 - (is.gcount() % 8);
            }
        }

    	if(buffer.size() != 64){
    	    break;
    	}

        uint32_t block[64];
        sha256::buffer_to_block(buffer, block);
        sha256::transform(digest, block, transforms);
        buffer.clear();
    }

    // Total number of hashed bits
    uint64_t total_bits = ((transforms*64 + buffer.size()) * 8) - min_len;

    // Padding
    if(min_len == 0){ buffer += (char) 0x80; }
    size_t orig_size = buffer.size();
    while(buffer.size() < 64){
        buffer += (char) 0x00;
    }

    uint32_t block[64];
    sha256::buffer_to_block(buffer, block);

    if(orig_size > 56){
        sha256::transform(digest, block, transforms);
        for(size_t i = 0; i < 14; i++){
            block[i] = 0;
        }
    }

    // Append total_bits, split this uint64_t into two uint32_t
    block[14] = (uint32_t) (total_bits >> 32);
    block[15] = (uint32_t) total_bits;
    uint32_t s0, s1;
    for(size_t i = 16; i < 64; i++){
        s0 = sha256::b_rol(block[i-15], 7) ^ sha256::b_rol(block[i-15], 18) ^ (block[i-15] >> 3);
        s1 = sha256::b_rol(block[i-2], 17) ^ sha256::b_rol(block[i-2], 19) ^ (block[i-2] >> 10);
        block[i] = block[i-16] + s0 + block[i-7] + s1;
    }

    sha256::transform(digest, block, transforms);

    // Hex std::string
    std::ostringstream result;
    for(size_t i = 0; i < 8; i++){
        result << std::hex << std::setfill('0') << std::setw(8) << digest[i];
    }

    return result.str();
}

// Hash function, input from a file
std::string sha_256(std::ifstream &in, int mode){
    // Variables declaration
    uint32_t digest[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::string buffer;
    uint64_t transforms = 0;
    int min_len = 0;

    while(true){
        if(mode == 0){
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
        }
        else if(mode == 1){
            int tmp;
            char sbuf_e[128], sbuf[64];
            in.read(sbuf_e, 128);

            size_t cnt = in.gcount();
            if(sbuf_e[in.gcount() - 1] == 10 && in.gcount() != 128){
                sbuf_e[in.gcount() - 1] = (char) 0;
                cnt--;
            }

            for(size_t i = 0; i < cnt / 2; i++){
                std::stringstream ss;
                ss << sbuf_e[i*2];
                ss << sbuf_e[(i*2)+1];

                ss >> std::hex >>  tmp;
                sbuf[i] = (char) tmp;
            }

            if(cnt % 2 != 0){
                std::stringstream ss;
                ss << sbuf_e[cnt - 1];
                ss << (char) 0x30;

                ss >> std::hex >> tmp;
                sbuf[(cnt - 1) / 2] = (char) (tmp | 0x08);

                buffer.append(sbuf, (cnt + 1) / 2);
                min_len = 4;
            }
            else{
                buffer.append(sbuf, cnt / 2);
            }
        }
        else if(mode == 2){
            char sbuf_b[512], sbuf[64] = {0};
            in.read(sbuf_b, 512);

            size_t cnt = in.gcount();
            if(sbuf_b[in.gcount() - 1] == 10 && in.gcount() != 512){
                sbuf_b[in.gcount() - 1] = (char) 0;
                cnt--;
            }

            for(size_t i = 0; i < cnt; i++){
                if(sbuf_b[i] == '1'){
                    sbuf[(int) i / 8] |= (0x01 << (7 - (i%8)));
                }
            }

            if(cnt % 8 == 0){
                buffer.append(sbuf,  cnt / 8);
            }
            else{
                sbuf[cnt / 8] |= ((0x01 << (7 - (cnt%8))));
                buffer.append(sbuf, (cnt / 8) + 1);
                min_len = 8 - (cnt % 8);
            }
        }

    	if(buffer.size() != 64){
    	    break;
    	}

        uint32_t block[64];
        sha256::buffer_to_block(buffer, block);
        sha256::transform(digest, block, transforms);
        buffer.clear();
    }

    // Total number of hashed bits
    uint64_t total_bits = ((transforms*64 + buffer.size()) * 8) - min_len;

    // Padding
    if(min_len == 0){ buffer += (char) 0x80; }
    size_t orig_size = buffer.size();
    while(buffer.size() < 64){
        buffer += (char) 0x00;
    }

    uint32_t block[64];
    sha256::buffer_to_block(buffer, block);

    if(orig_size > 56){
        sha256::transform(digest, block, transforms);
        for(size_t i = 0; i < 14; i++){
            block[i] = 0;
        }
    }

    // Append total_bits, split this uint64_t into two uint32_t
    block[14] = (uint32_t) (total_bits >> 32);
    block[15] = (uint32_t) total_bits;
    uint32_t s0, s1;
    for(size_t i = 16; i < 64; i++){
        s0 = sha256::b_rol(block[i-15], 7) ^ sha256::b_rol(block[i-15], 18) ^ (block[i-15] >> 3);
        s1 = sha256::b_rol(block[i-2], 17) ^ sha256::b_rol(block[i-2], 19) ^ (block[i-2] >> 10);
        block[i] = block[i-16] + s0 + block[i-7] + s1;
    }

    sha256::transform(digest, block, transforms);

    // Hex std::string
    std::ostringstream result;
    for(size_t i = 0; i < 8; i++){
        result << std::hex << std::setfill('0') << std::setw(8) << digest[i];
    }

    return result.str();
}
