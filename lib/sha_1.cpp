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
#include "../include/sha_1.hpp"


namespace sha1
{
    // Leftrotate a 32bit number
    uint32_t rol(uint32_t value, size_t bits){
        return (value << bits) | (value >> (32 - bits));
    }

    // Hash a single 512-bit block. This is the core of the algorithm
    void transform(uint32_t digest[5], uint32_t block[80], uint64_t &transforms){
        uint32_t v[5], f, tmp;
        for(int i = 0; i < 5; i++){ v[i] = digest[i]; }

        for(int i = 0; i < 80; i++){
            if(i < 20){
                f = (v[3] ^ (v[1] & (v[2] ^ v[3]))) + 0x5a827999;
            }
            else if(i < 40){
                f = (v[1] ^ v[2] ^ v[3]) + 0x6ed9eba1;
            }
            else if(i < 60){
                f = ((v[1] & v[2]) | (v[3] & (v[1] | v[2]))) + 0x8f1bbcdc;
            }
            else{
                f = (v[1] ^ v[2] ^ v[3]) + 0xca62c1d6;
            }

            tmp = sha1::rol(v[0], 5) + f + v[4] + block[i];
            v[4] = v[3];
            v[3] = v[2];
            v[2] = sha1::rol(v[1], 30);
            v[1] = v[0];
            v[0] = tmp;
        }

        for(int i = 0; i < 5; i++){ digest[i] += v[i]; }

        // Count the number of transformations
        transforms++;
    }

    // Convert a 512bits buffer into 80 32bits words
    void buffer_to_block(std::string &buffer, uint32_t block[80]){
        for(size_t i = 0; i < 16; i++){
            block[i] = (buffer[4*i+3] & 0xff) | (buffer[4*i+2] & 0xff)<<8 | (buffer[4*i+1] & 0xff)<<16 | (buffer[4*i+0] & 0xff)<<24;
        }

        for(size_t i = 16; i < 80; i++){
            block[i] = sha1::rol(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
        }
    }
}

// Hash function, input from a string
std::string sha_1(const std::string &s, int mode){
    // Variables declaration
    uint32_t digest[5];
    std::string buffer;
    uint64_t transforms = 0;
    int min_len = 0;

    // SHA1 initialization constants
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

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

        uint32_t block[80];
        sha1::buffer_to_block(buffer, block);
        sha1::transform(digest, block, transforms);
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

    uint32_t block[80];
    sha1::buffer_to_block(buffer, block);

    if(orig_size > 56){
        sha1::transform(digest, block, transforms);
        for(size_t i = 0; i < 14; i++){
            block[i] = 0;
        }
    }

    // Append total_bits, split this uint64_t into two uint32_t
    block[14] = (uint32_t) (total_bits >> 32);
    block[15] = (uint32_t) total_bits;
    for(int i = 16; i < 80; i++){
        block[i] = sha1::rol(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
    }

    sha1::transform(digest, block, transforms);

    // Hex std::string
    std::ostringstream result;
    for(size_t i = 0; i < 5; i++){
        result << std::hex << std::setfill('0') << std::setw(8) << digest[i];
    }

    return result.str();
}

// Hash function, input from a file
std::string sha_1(std::ifstream &in, int mode){
    // Variables declaration
    uint32_t digest[5];
    std::string buffer;
    uint64_t transforms = 0;
    int min_len = 0;

    // SHA1 initialization constants
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

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

        uint32_t block[80];
        sha1::buffer_to_block(buffer, block);
        sha1::transform(digest, block, transforms);
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

    uint32_t block[80];
    sha1::buffer_to_block(buffer, block);

    if(orig_size > 56){
        sha1::transform(digest, block, transforms);
        for(size_t i = 0; i < 14; i++){
            block[i] = 0;
        }
    }

    // Append total_bits, split this uint64_t into two uint32_t
    block[14] = (uint32_t) (total_bits >> 32);
    block[15] = (uint32_t) total_bits;
    for(int i = 16; i < 80; i++){
        block[i] = sha1::rol(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
    }

    sha1::transform(digest, block, transforms);

    // Hex std::string
    std::ostringstream result;
    for(size_t i = 0; i < 5; i++){
        result << std::hex << std::setfill('0') << std::setw(8) << digest[i];
    }

    return result.str();
}
