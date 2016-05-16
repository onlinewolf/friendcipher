/*
friendcipher::Keccak
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
#include <cstring>
#include "fckeccak.h"
#include "fcexception.h"

namespace friendcipher{

extern "C"{
//original: https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/CompactFIPS202/Keccak-readable-and-compact.c
//licence: http://creativecommons.org/publicdomain/zero/1.0/

#ifndef LITTLE_ENDIAN
static uint64_t load64(const uint8_t *x){
    int i;
    uint64_t u=0;

    for(i=7; i>=0; --i){
        u <<= 8;
        u |= x[i];
    }
    return u;
}

static void store64(uint8_t *x, uint64_t u){
    uint32_t i;

    for(i=0; i<8; ++i){
        x[i] = u;
        u >>= 8;
    }
}

static void xor64(uint8_t *x, uint64_t u){
    uint32_t i;

    for(i=0; i<8; ++i){
        x[i] ^= u;
        u >>= 8;
    }
}
#endif

#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#define CALC(x, y) ((x)+5*(y))

#ifdef LITTLE_ENDIAN
    #define readLane(x, y)          (((uint64_t*)state)[CALC(x, y)])
    #define writeLane(x, y, lane)   (((uint64_t*)state)[CALC(x, y)]) = (lane)
    #define XORLane(x, y, lane)     (((uint64_t*)state)[CALC(x, y)]) ^= (lane)
#else
    #define readLane(x, y)          load64((uint8_t*)state+sizeof(uint64_t)*CALC(x, y))
    #define writeLane(x, y, lane)   store64((uint8_t*)state+sizeof(uint64_t)*CALC(x, y), lane)
    #define XORLane(x, y, lane)     xor64((uint8_t*)state+sizeof(uint64_t)*CALC(x, y), lane)
#endif

int LFSR86540(uint8_t *LFSR){
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

void KeccakF1600_StatePermute(void *state){
    uint32_t round, x, y, j, t;
    uint8_t LFSRstate = 0x01;

    for(round=0; round<24; round++){
        {
            uint64_t C[5], D;

            for(x=0; x<5; x++)
                C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
            for(x=0; x<5; x++){
                D = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
                for (y=0; y<5; y++)
                    XORLane(x, y, D);
            }
        }

        {
            uint64_t current, temp;
            x = 1; y = 0;
            current = readLane(x, y);
            for(t=0; t<24; t++){
                uint32_t r = ((t+1)*(t+2)/2)%64;
                uint32_t Y = (2*x+3*y)%5; x = y; y = Y;
                temp = readLane(x, y);
                writeLane(x, y, ROL64(current, r));
                current = temp;
            }
        }

        {
            uint64_t temp[5];
            for(y=0; y<5; y++){
                for(x=0; x<5; x++)
                    temp[x] = readLane(x, y);
                for(x=0; x<5; x++)
                    writeLane(x, y, temp[x] ^((~temp[(x+1)%5]) & temp[(x+2)%5]));
            }
        }

        {
            for(j=0; j<7; j++){
                uint32_t bitPosition = (1<<j)-1; //2^j-1
                if (LFSR86540(&LFSRstate))
                    XORLane(0, 0, (uint64_t)1<<bitPosition);
            }
        }
    }
}

}//extern C


//"static method"
bool keccakBitLenCheck(int bitLen){
    return bitLen == 224 || bitLen == 256 || bitLen == 384 || bitLen == 512;
}

//class
Keccak::Keccak(int bitLen):kMdBitLen(bitLen), kMdLen(bitLen/8){
    if(!keccakBitLenCheck(bitLen))
        throw invalidArgsException;

    switch(bitLen){
        case 224:
            rateInBytes_ = 144;
        break;

        case 256:
            rateInBytes_ = 136;
        break;

        case 384:
            rateInBytes_ = 104;
        break;

        case 512:
            rateInBytes_ = 72;
        break;

        default:
        break;
    }
    forUpdate_ = new uint8_t[rateInBytes_];
    reset();
}

void Keccak::reset(){
    updatePos_ = 0;
    memset(state_, 0, sizeof(state_));
}

void Keccak::update(const uint8_t *data, int len){
    if(!data || len <= 0)
        return;

    int reCount = 0;
    for(int j=0; j<len; j++){
        forUpdate_[updatePos_ + reCount] = data[j];
        reCount++;
        if(updatePos_ + reCount > rateInBytes_-1){
            updatePos_ = 0;
            reCount = 0;
            for(int x=0; x < rateInBytes_; x++)
                state_[x] ^= forUpdate_[x];
            KeccakF1600_StatePermute(state_);
        }
    }

    updatePos_ += reCount;
}

void Keccak::finish(uint8_t *out){
    if(!out)
        return;

    if(updatePos_ > 0){
        for(int j=0; j<updatePos_; j++){
            state_[j] ^= forUpdate_[j];
        }

        state_[updatePos_] ^= kDelimitedSuffix_;
        state_[rateInBytes_-1] ^= 0x80;
        KeccakF1600_StatePermute(state_);
    }

    memcpy(out, state_, kMdLen);
    reset();
}

Keccak::~Keccak(){
    delete[] forUpdate_;
}

}//namesapce
