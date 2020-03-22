#include <cstdint>
#include <stdio.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include "sha_512.hpp"

namespace sha512
{
    // Table of round constants
    static const uint64_t k[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
                                   0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
                                   0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                                   0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                                   0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
                                   0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                                   0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
                                   0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                                   0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                                   0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
                                   0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
                                   0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                                   0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
                                   0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
                                   0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                                   0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

    // Rightrotate a 64bit number (back rol)
    uint64_t b_rol(uint64_t value, size_t bits){
        return (value << (64 - bits) | (value >> bits));
    }

    // Hash a single 1024-bit block. This is the core of the algorithm
    void transform(uint64_t digest[8], uint64_t block[80], uint64_t &transforms){
        uint64_t a = digest[0];
        uint64_t b = digest[1];
        uint64_t c = digest[2];
        uint64_t d = digest[3];
        uint64_t e = digest[4];
        uint64_t f = digest[5];
        uint64_t g = digest[6];
        uint64_t h = digest[7];
        uint64_t s0, s1, t1, t2, maj, ch;

        for(int i = 0; i < 80; i++){
            s0 = sha512::b_rol(a, 28) ^ sha512::b_rol(a, 34) ^ sha512::b_rol(a, 39);
            maj = (a & b) ^ (a & c) ^ (b & c);
            t2 = s0 + maj;

            s1 = sha512::b_rol(e, 14) ^ sha512::b_rol(e, 18) ^ sha512::b_rol(e, 41);
            ch = (e & f) ^ ((~e) & g);
            t1 = h + s1 + ch + sha512::k[i] + block[i];

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
        digest[5] += f;
        digest[6] += g;
        digest[7] += h;

        // Count the number of transformations
        transforms++;
    }

    // Convert a 1024bits buffer into 80 64bits words
    void buffer_to_block(std::string &buffer, uint64_t block[80]){
        for(size_t i = 0; i < 16; i++){
            block[i] = 0;
            for(size_t j = 0; j < 8; j++){
                block[i] |= ((((uint64_t)buffer[8*i+j]) & 0x00000000000000ff)<<(56-(j*8)));
            }
        }

        uint64_t s0, s1;
        for(size_t i = 16; i < 80; i++){
            s0 = sha512::b_rol(block[i-15], 1) ^ sha512::b_rol(block[i-15], 8) ^ (block[i-15] >> 7);
            s1 = sha512::b_rol(block[i-2], 19) ^ sha512::b_rol(block[i-2], 61) ^ (block[i-2] >> 6);
            block[i] = block[i-16] + s0 + block[i-7] + s1;
        }
    }
}

// Hash function, input from a string
std::string sha_512(const std::string &s, int mode){
    // Variables declaration
    uint64_t digest[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                          0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
    std::string buffer;
    uint64_t transforms = 0;

    std::istringstream is(s);

    while(true){
        if(mode == 0){
            char sbuf[128];
            is.read(sbuf, 128);
            buffer.append(sbuf, (std::size_t) is.gcount());
        }
        else if(mode == 1){
            int tmp;
            char sbuf_e[256], sbuf[128];
            is.read(sbuf_e, 256);

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
                ss << 0x30;

                ss >> std::hex >> tmp;
                sbuf[(is.gcount() - 1) / 2] = (char) tmp;

                buffer.append(sbuf, (std::size_t) ((is.gcount() + 1) / 2));
            }
            else{
                buffer.append(sbuf, (std::size_t) is.gcount() / 2);
            }
        }
        else if(mode == 2){
            char sbuf_b[1024], sbuf[128] = {0};
            is.read(sbuf_b, 1024);

            for(size_t i = 0; i < is.gcount(); i++){
                if(sbuf_b[i] == '1'){
                    sbuf[(int) i / 8] |= (0x01 << (7 - (i%8)));
                }
            }

            if(is.gcount() % 8 == 0){
                buffer.append(sbuf, (std::size_t) is.gcount() / 8);
            }
            else{
                buffer.append(sbuf, (std::size_t) ((is.gcount() / 8) + 1));
            }
        }

    	if(buffer.size() != 128){
    	    break;
    	}

        uint64_t block[80];
        sha512::buffer_to_block(buffer, block);
        sha512::transform(digest, block, transforms);
        buffer.clear();
    }

    // Total number of hashed bits
    uint64_t total_bits = (transforms*128 + buffer.size()) * 8;

    // Padding
    buffer += (char) 0x80;
    size_t orig_size = buffer.size();
    while(buffer.size() < 128){
        buffer += (char) 0x00;
    }

    uint64_t block[80];
    sha512::buffer_to_block(buffer, block);

    if(orig_size > 112){
        sha512::transform(digest, block, transforms);
        for(size_t i = 0; i < 14; i++){
            block[i] = 0;
        }
    }

    // Append total_bits, split this uint128_t into two uint64_t
    block[14] = (uint64_t) 0x00;
    block[15] = total_bits;

    uint64_t s0, s1;
    for(size_t i = 16; i < 80; i++){
        s0 = sha512::b_rol(block[i-15], 1) ^ sha512::b_rol(block[i-15], 8) ^ (block[i-15] >> 7);
        s1 = sha512::b_rol(block[i-2], 19) ^ sha512::b_rol(block[i-2], 61) ^ (block[i-2] >> 6);
        block[i] = block[i-16] + s0 + block[i-7] + s1;
    }

    sha512::transform(digest, block, transforms);

    // Hex std::string
    std::ostringstream result;
    for(size_t i = 0; i < 8; i++){
        result << std::hex << std::setfill('0') << std::setw(8) << digest[i];
    }

    return result.str();
}

// Hash function, input from a file
std::string sha_512(std::ifstream &in, int mode){
    // Variables declaration
    uint64_t digest[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                          0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
    std::string buffer;
    uint64_t transforms = 0;

    while(true){
        if(mode == 0){
            char sbuf[128];
            in.read(sbuf, 128);

            size_t cnt = in.gcount();
            for(size_t i = 0; i < in.gcount(); i++){
                if(sbuf[i] == 10 && i == in.gcount() - 1 && in.gcount() != 128){
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
            char sbuf_e[256], sbuf[128];
            in.read(sbuf_e, 256);

            size_t cnt = in.gcount();
            if(sbuf_e[in.gcount() - 1] == 10 && in.gcount() != 256){
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
                ss << 0x30;

                ss >> std::hex >> tmp;
                sbuf[(cnt - 1) / 2] = (char) tmp;

                buffer.append(sbuf, (cnt + 1) / 2);
            }
            else{
                buffer.append(sbuf, cnt / 2);
            }
        }
        else if(mode == 2){
            char sbuf_b[1024], sbuf[128] = {0};
            in.read(sbuf_b, 1024);

            size_t cnt = in.gcount();
            if(sbuf_b[in.gcount() - 1] == 10 && in.gcount() != 1024){
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
                buffer.append(sbuf, (cnt / 8) + 1);
            }
        }

    	if(buffer.size() != 128){
    	    break;
    	}

        uint64_t block[80];
        sha512::buffer_to_block(buffer, block);
        sha512::transform(digest, block, transforms);
        buffer.clear();
    }

    // Total number of hashed bits
    uint64_t total_bits = (transforms*64 + buffer.size()) * 8;

    // Padding
    buffer += (char) 0x80;
    size_t orig_size = buffer.size();
    while(buffer.size() < 128){
        buffer += (char) 0x00;
    }

    uint64_t block[80];
    sha512::buffer_to_block(buffer, block);

    if(orig_size > 112){
        sha512::transform(digest, block, transforms);
        for(size_t i = 0; i < 14; i++){
            block[i] = 0;
        }
    }

    // Append total_bits, split this uint128_t into two uint64_t
    block[14] = (uint64_t) 0x00;
    block[15] = total_bits;

    uint64_t s0, s1;
    for(int i = 16; i < 80; i++){
        s0 = sha512::b_rol(block[i-15], 1) ^ sha512::b_rol(block[i-15], 8) ^ (block[i-15] >> 7);
        s1 = sha512::b_rol(block[i-2], 19) ^ sha512::b_rol(block[i-2], 61) ^ (block[i-2] >> 6);
        block[i] = block[i-16] + s0 + block[i-7] + s1;
    }

    sha512::transform(digest, block, transforms);

    // Hex std::string
    std::ostringstream result;
    for(size_t i = 0; i < 8; i++){
        result << std::hex << std::setfill('0') << std::setw(8) << digest[i];
    }

    return result.str();
}
