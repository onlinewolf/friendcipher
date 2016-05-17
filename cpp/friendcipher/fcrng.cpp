/*
friendcipher::RngWithKeccak
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

URL: https://github.com/onlinewolf/friendcipher
*/
#include "fcrng.h"
#include "fcexception.h"

namespace friendcipher{

RngWithHash::RngWithHash(int bitLen): kMdBitLen(bitLen), kMdLen(bitLen/8), hash_(bitLen){
    if(!keccakBitLenCheck(bitLen))
        throw invalidArgsException;

    seed_ = new uint8_t[kMdLen];
    randMd_ = new uint8_t[kMdLen];
    init_ = false;
}

bool RngWithHash::init(const uint8_t *seed, int seedLen, const uint8_t *salt, int saltLen){
    if(!seed || seedLen <= 0)
        return false;

    hash_.update(seed, seedLen);

    if(salt && saltLen > 0)
        hash_.update(salt, saltLen);

    hash_.finish(seed_);

    hash_.update(seed_, kMdLen);
    hash_.update(seed_, kMdLen);
    hash_.finish(randMd_);
    init_ = true;
    p_ = 0;

    return true;
}

bool RngWithHash::isInited(){
    return init_;
}

bool RngWithHash::reSeed(const uint8_t *seed, int seedLen){
    if(!seed || seedLen <= 0)
        return false;

    hash_.update(seed_, kMdLen);
    hash_.update(seed, seedLen);
    hash_.finish(seed_);

    hash_.update(seed_, kMdLen);
    hash_.update(seed_, kMdLen);
    hash_.finish(randMd_);
    init_ = true;
    p_ = 0;

    return true;
}

uint8_t RngWithHash::random8bit(){
    if(!init_)
        return 0;

    if(p_ >= kMdLen){
        hash_.update(randMd_, kMdLen);
        hash_.update(seed_, kMdLen);
        hash_.finish(randMd_);
        p_ = 0;
    }
    uint8_t temp = randMd_[p_];
    p_++;
    return temp;
}

uint32_t RngWithHash::random32bit(){
    if(!init_)
        return 0;

    uint32_t temp;
    uint8_t * t = (uint8_t *)&temp;
    for(int i=0; i<4; i++)
        t[i] = random8bit();

    return temp;
}

RngWithHash::~RngWithHash(){
    delete[] seed_;
    delete[] randMd_;
}

}//namespace
