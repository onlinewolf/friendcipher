/*
FriendCryptMixer
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
#include <3rd/keccak.h>
#include "fcmixer.h"
#include "fcexception.h"

namespace friendcrypt{

//class
MixWithKeccak::MixWithKeccak(uint8_t* salt, long len, long digestLen): kSaltLen(len), kDigestLen(digestLen){
    if(!salt || len <= 0 || digestLen > 64 || (digestLen % 32) != 0)
        throw invalidArgsException;

    salt_ = new uint8_t[len];
    tempSHKLen_ = len+kDigestLen+1;
    tempSHK_ = new uint8_t[tempSHKLen_];
    digest_ = new uint8_t[kDigestLen];
    std::memcpy(salt_, salt, len);
}

void MixWithKeccak::listMix(uint8_t* data, long start, long len, uint8_t key){
    if(!data || len<=0 || start < 0)
        return;


    uint8_t *noMix = new uint8_t[len];//copy data for mix
    std::memcpy(noMix, &data[start], len);

    std::memcpy(tempSHK_, salt_, kSaltLen);//copy full salt

    tempSHK_[kSaltLen] = key;//copy the key to relative end
    keccak(tempSHK_, kSaltLen+1, digest_, kDigestLen);//create hash for random numbers

    long randNumber;
    long mixLen = len;
    long d=start;
    while(true){
        for(long i=0; i<kDigestLen; i++){
            randNumber = calcConvert(digest_[i], 255.0, 0, mixLen);//get a "random number" for list

            data[d] = noMix[randNumber];
            d++;

            noMix[randNumber] = noMix[mixLen-1];

            mixLen--;//lower list
            if(mixLen == 0)//no more item
                break;
        }

        if(mixLen == 0)//no more item
            break;
        //get new "random" numbers
        std::memcpy(&tempSHK_[kSaltLen], digest_, kDigestLen);//copy last hash
        tempSHK_[tempSHKLen_-1] = key;//copy the key to end
        keccak(tempSHK_, tempSHKLen_, digest_, kDigestLen);//create new hash with last hash
    }
    //correct end
    delete[] noMix;
}

void MixWithKeccak::listReverseMix(uint8_t* data, long start, long len, uint8_t key){
    if(!data || len<=0 || start < 0)
        return;

    long *nomix = new long[len];//list for reverse
    for(long i=0; i<len; i++)
        nomix[i] = i;

    uint8_t *copyedData = new uint8_t[len];//copy data for mix
    std::memcpy(copyedData, &data[start], len);

    std::memcpy(tempSHK_, salt_, kSaltLen);//copy full salt

    tempSHK_[kSaltLen] = key;//copy the key to relative end
    keccak(tempSHK_, kSaltLen+1, digest_, kDigestLen);//create hash for random numbers

    long randNumber;
    long mixLen = len;
    long d=start;
    while(true){
        for(long i=0; i<kDigestLen; i++){
            randNumber = calcConvert(digest_[i], 255.0, 0, mixLen);//get a "random number" for list

            data[nomix[randNumber]+start] = copyedData[d-start];
            d++;

            nomix[randNumber] = nomix[mixLen-1];

            mixLen--;//lower list
            if(mixLen == 0)//no more item
                break;
        }

        if(mixLen == 0)//no more item
            break;
        //get new "random" numbers
        std::memcpy(&tempSHK_[kSaltLen], digest_, kDigestLen);//copy last hash
        tempSHK_[tempSHKLen_-1] = key;//copy the key to end
        keccak(tempSHK_, tempSHKLen_, digest_, kDigestLen);//create new hash with last hash
    }
    //correct end
    delete[] nomix;
    delete[] copyedData;
}

void MixWithKeccak::mix(uint8_t* data, long len, uint8_t* key, long klen, long bmax){
    if(!data || !key || len<=0 || klen <= 0 || bmax <= 0)
        return;

    if(klen==1){
        listMix(data, 0, len, key[0]);
    }else{
        long bs;
        long sum = 0;
        for(long i=0; i<klen; i++){
            bs = calcBlockSize(key[i], bmax);//calc block size

            if((i+1) == klen)//last block
                bs = len - sum;

            if(((sum+bs)<=len)){//only correct len
                listMix(data, sum, bs, key[i]);
                sum += bs;//next block
            }

            if((i+1) == klen)//mix all
                listMix(data, 0, len, key[i]);
        }
    }
}

void MixWithKeccak::reverseMix(uint8_t* data, long len, uint8_t* key, long klen, long bmax){
    if(!data || !key || len<=0 || klen <= 0 || bmax <= 0)
        return;

    if(klen==1){
        listReverseMix(data, 0, len, key[0]);
    }else{
        long bs;
        long sum = 0;
        for(long i=0; i<klen; i++){
            bs = calcBlockSize(key[i], bmax);//calc block size

            if(i == 0)//reverse mix all
                listReverseMix(data, 0, len, key[klen-1]);

            if((i+1) == klen)//last block
                bs = len - sum;

            if((sum+bs)<=len){//only correct len
                listReverseMix(data, sum, bs, key[i]);
                sum += bs;//next block
            }
        }
    }
}

MixWithKeccak::~MixWithKeccak(){
    delete[] salt_;
    delete[] tempSHK_;
    delete[] digest_;
}


//"static" functions
long calcBlockSize(uint8_t key, long bmax){
    if(bmax<=0)
        return 0;

    long bmin = bmax/2;
    return std::lround((key/255.0 * (bmin-1)) + bmin);
}

long calcConvert(long x, double xmax, long min, long max){
    if(x<0 || xmax<=0 || min<0 || max<=0)
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

}
