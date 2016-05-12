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
aint with this program.  If not, see <http://www.gnu.org/licenses/>.

URL: https://github.com/onlinewolf/friendcrypt
*/
#ifndef FCRNG_H
#define FCRNG_H
#include <cstdint>
#include <fckeccak.h>

namespace friendcrypt{

/**
 * @brief The Rng class
 * Powerful Random Number Generator with Keccak
 * (Not thread safe!)
 */
class Rng{
    Keccak hash_;
    uint8_t *seed_;
    uint8_t *randMd_;
    uint8_t p_;
    bool init_;
public:
    /**
     * @brief kMdLen
     * Message digest byte length
     */
    const int kMdLen;
    /**
     * @brief kMdBitLen
     * Message digest bit length
     */
    const int kMdBitLen;

    /**
     * @brief Rng
     * Random Number Generator with Keccak
     * @param bitLen Bit size of Keccak: 224, 256, 384, 512 bit
     * @throw invalidArgsException if bitLen is invalid
     */
    explicit Rng(int bitLen);

    /**
     * @brief init
     * Initialization/reset with seed (salt is optional)
     * @param seed Seed data
     * @param seedLen Seed data length
     * @param salt Salt (can be nullptr)
     * @param saltLen Salt length (can be 0)
     * @return false if seed is nullptr or seedLen is <=0
     */
    bool init(const uint8_t *seed, int seedLen, const uint8_t *salt, int saltLen);

    /**
     * @brief isInit
     * Rng initialization check
     * @return true if init() is called
     */
    bool isInited();

    /**
     * @brief reSeed
     * Create new seed with last seed (the last seed is unkown if init() isn't called)
     * @param seed New seed
     * @param seedLen New seed length
     * @return false if seed is nullptr or seedLen is <=0
     */
    bool reSeed(const uint8_t *seed, int seedLen);

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

    /**
     * @brief ~Rng
     * Delete *seed_, *randMd_
     */
    virtual ~Rng();

    //disabled
    Rng(const Rng& other)=delete;
    Rng(Rng&& other)=delete;
    Rng& operator=(const Rng& other)=delete;
    Rng& operator=(Rng&& other)=delete;
};

}//namespace
#endif // FCRNG_H
