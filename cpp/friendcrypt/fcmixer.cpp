/*
friendcrypt::MixWithKeccak
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
#include <cmath>
#include <cstring>
#include "fcmixer.h"
#include "fcexception.h"

namespace friendcrypt{

//class
MixWithKeccak::MixWithKeccak(const uint8_t *key, long keyLen, const uint8_t *iv, long ivLen, const uint8_t* salt, long saltLen):
            hash_(kDigestBitLen), key_(key), iv_(iv), salt_(salt){
    if(!key || keyLen <= 0 || !iv || ivLen <= 0 || !salt || saltLen <= 0)
        throw invalidArgsException;

    keyLen_ = keyLen;
    ivLen_ = ivLen;
    saltLen_ = saltLen;
}

void MixWithKeccak::listMix(uint8_t* tempIn, uint8_t* dataOut, long len, Rng &rng){
    if(!tempIn || !dataOut || len<=0)
        return;

    long random;
    for(long i=0, mlen=len; i<len; i++, mlen--){
        random = rng.random32bit() % mlen;
        dataOut[i] = tempIn[random];
        tempIn[random] = tempIn[mlen-1];
    }
}

void MixWithKeccak::listReverseMix(uint8_t* tempIn, uint8_t* dataOut, long len, Rng &rng){
    if(!tempIn || !dataOut || len<=0)
        return;

    for(long i=0; i<kDigestLen; i++)
        listTemp_[i] = i;

    long random;
    for(long i=0, mlen=len; i<len; i++, mlen--){
        random = rng.random32bit() % mlen;
        dataOut[listTemp_[random]] = tempIn[i];
        listTemp_[random] = listTemp_[mlen-1];
    }
}

bool MixWithKeccak::mix(const uint8_t* dataIn, uint8_t *dataOut, long len, uint32_t counter){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    Rng rng(key_, keyLen_, salt_, saltLen_);
    hash_.update(iv_, ivLen_);
    hash_.update(salt_, saltLen_);
    if(counter != 0)
        hash_.update((uint8_t *)&counter, 4);
    hash_.finish(temp_);
    rng.reSeed(temp_, kDigestLen);

    long blockLen = calcBlockSize(rng.random32bit(), kDigestLen);
    long neg = 0;
    for(long i=0; i<len; i++){
        temp_[neg] = dataIn[i];
        neg++;
        if(neg > blockLen){
            listMix(temp_, &dataOut[i-blockLen], neg, rng);
            neg = 0;
            if(i!=(len-1)){
                blockLen = calcBlockSize(rng.random32bit(), kDigestLen);
            }
        }
    }

    if(neg!=0){
        listMix(temp_, &dataOut[len-neg], neg, rng);
    }

    return true;
}

bool MixWithKeccak::reverseMix(const uint8_t* dataIn, uint8_t *dataOut, long len, uint32_t counter){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    Rng rng(key_, keyLen_, salt_, saltLen_);
    hash_.update(iv_, ivLen_);
    hash_.update(salt_, saltLen_);
    if(counter != 0)
        hash_.update((uint8_t *)&counter, 4);
    hash_.finish(temp_);
    rng.reSeed(temp_, kDigestLen);

    long blockLen = calcBlockSize(rng.random32bit(), kDigestLen);
    long neg = 0;
    for(long i=0; i<len; i++){
        temp_[neg] = dataIn[i];
        neg++;
        if(neg > blockLen){
            listReverseMix(temp_, &dataOut[i-blockLen], neg, rng);
            neg = 0;
            if(i!=(len-1)){
                blockLen = calcBlockSize(rng.random32bit(), kDigestLen);
            }
        }
    }

    if(neg!=0){
        listReverseMix(temp_, &dataOut[len-neg], neg, rng);
    }

    return true;
}

bool MixWithKeccak::crazyMix(const uint8_t *dataIn, uint8_t *dataOut, long len){
    if(!dataIn || !dataOut || len <= 0)
        return false;


    Rng rng(key_, keyLen_, salt_, saltLen_);
    hash_.update(iv_, ivLen_);
    hash_.update(salt_, saltLen_);
    hash_.finish(temp_);
    rng.reSeed(temp_, kDigestLen);

    const uint8_t *temp = dataIn;
    int crazyNumber = calcCrazy(rng.random32bit(), kMinCrazy, kMaxCrazy);

    if(crazyNumber % 2 != 1)
        crazyNumber++;

    for(int i=0; i<crazyNumber; i++){
        if(!mix(temp, dataOut, len, i))
            return false;
        if(i == 0){
            temp = dataOut;
        }
    }
    return true;
}

bool MixWithKeccak::reverseCrazyMix(const uint8_t *dataIn, uint8_t *dataOut, long len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    Rng rng(key_, keyLen_, salt_, saltLen_);
    hash_.update(iv_, ivLen_);
    hash_.update(salt_, saltLen_);
    hash_.finish(temp_);
    rng.reSeed(temp_, kDigestLen);

    const uint8_t *temp = dataIn;
    int crazyNumber = calcCrazy(rng.random32bit(), kMinCrazy, kMaxCrazy);

    if(crazyNumber % 2 != 1)
        crazyNumber++;

    for(int i=crazyNumber-1; i>=0; i--){
        if(!reverseMix(temp, dataOut, len, i))
            return false;
        if(i == crazyNumber-1){
            temp = dataOut;
        }
    }
    return true;
}

MixWithKeccak::~MixWithKeccak(){
    //
}


//"static" functions
long calcBlockSize(uint32_t x, long bmax){
    if(bmax<=1)
        return 0;

    long bmin = bmax/2;
    x = x % bmin;
    return x + bmin;
}

long calcConvert(long x, double xmax, long min, long max){
    if(x<0 || xmax<=0 || min<0 || max<=1)
        return 0;

    if(x>xmax)
        return 0;

    if(min>max){
        long temp = min;
        min = max;
        max = temp;
    }

    return std::lround((x/xmax * (max-min-1)) + min);
}


long calcCrazy(uint32_t x, uint8_t min, uint8_t max){
    if(max <= 1)
        return 1;

    if(min == 0)
        min = 1;

    if(min>max){
        uint8_t temp = min;
        min = max;
        max = temp;
    }

    x = x % (max - min);
    return x + min;
}

}
