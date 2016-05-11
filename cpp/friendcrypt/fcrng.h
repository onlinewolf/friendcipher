/*
friendcrypt::Rng
Copyright (C) 2016 OnlineWolf

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

URL: https://github.com/onlinewolf/friendcrypt
*/
#ifndef FCRNG_H
#define FCRNG_H
#include <cstdint>
#include <fckeccak.h>

namespace friendcrypt{

/**
 * @brief The Rng class
 * Random Number Generator with Keccak
 */
class Rng{
    static const long kMdLen = 64;
    static const long kMdBitLen = kMdLen*8;
    Keccak hash_;
    uint8_t seed_[kMdLen];
    uint8_t randMd_[kMdLen];
    uint8_t p_;
public:
    /**
     * @brief Rng
     * Initialization with seed (salt is optional)
     * @param seed Seed data
     * @param seedLen Seed data length
     * @param salt Salt (can be nullptr)
     * @param saltLen Salt length (can be 0)
     * @throw invalidArgsException if seed is nullptr or seedLen is <=0
     */
    explicit Rng(const uint8_t *seed, long seedLen, const uint8_t *salt, long saltLen);

    /**
     * @brief reSeed
     * Create new seed with last seed
     * @param seed New seed
     * @param seedLen New seed length
     * @throw invalidArgsException if seed is nullptr or seedLen is <=0
     */
    void reSeed(const uint8_t *seed, long seedLen);

    /**
     * @brief random8bit
     * 8 bit random number
     * @return random number
     */
    uint8_t random8bit();

    /**
     * @brief random32bit
     * 32 bit random number
     * @return random number
     */
    uint32_t random32bit();

    //disabled
    Rng(const Rng& other)=delete;
    Rng(Rng&& other)=delete;
    Rng& operator=(const Rng& other)=delete;
    Rng& operator=(Rng&& other)=delete;
};

}//namespace
#endif // FCRNG_H
