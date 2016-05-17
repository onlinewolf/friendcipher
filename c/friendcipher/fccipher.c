/*
FriendCipher
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

#include <string.h>
#include <time.h>
#include "fccipher.h"

//--------------------------------------------------------------
//--------------------------------------------------------------
//original: https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/CompactFIPS202/Keccak-readable-and-compact.c
//licence: http://creativecommons.org/publicdomain/zero/1.0/

#ifndef FC_LITTLE_ENDIAN
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

#ifdef FC_LITTLE_ENDIAN
    #define readLane(x, y)          (((uint64_t*)state)[CALC(x, y)])
    #define writeLane(x, y, lane)   (((uint64_t*)state)[CALC(x, y)]) = (lane)
    #define XORLane(x, y, lane)     (((uint64_t*)state)[CALC(x, y)]) ^= (lane)
#else
    #define readLane(x, y)          load64((uint8_t*)state+sizeof(uint64_t)*CALC(x, y))
    #define writeLane(x, y, lane)   store64((uint8_t*)state+sizeof(uint64_t)*CALC(x, y), lane)
    #define XORLane(x, y, lane)     xor64((uint8_t*)state+sizeof(uint64_t)*CALC(x, y), lane)
#endif

static int LFSR86540(uint8_t *LFSR){
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

static void KeccakF1600_StatePermute(void *state){
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
//--------------------------------------------------------------
//--------------------------------------------------------------


static void reset(fc_hash_t *context){
    if(!context)
        return;

    context->updatePos = 0;
    memset(context->state, 0, sizeof(context->state));
}

void fc_hashInit(fc_hash_t *context, int bitLen){
    if(!context)
        return;

    memset(context, 0, sizeof(fc_hash_t));
    switch(bitLen){
        case 224:
            context->rateInBytes = FC_HASH_UPDATE_MAX_LENGTH;
        break;

        case 256:
            context->rateInBytes = 136;
        break;

        case 384:
            context->rateInBytes = 104;
        break;

        case 512:
            context->rateInBytes = 72;
        break;

        default:
            context->rateInBytes = FC_HASH_UPDATE_MAX_LENGTH;
        break;
    }

    context->mdLen = bitLen/8;
}

void fc_hashUpdate(fc_hash_t *context, const uint8_t *data, int len){
    if(!context || !data || len <= 0)
        return;

    int reCount = 0;
    int j, x;
    for(j=0; j<len; j++){
        context->forUpdate[context->updatePos + reCount] = data[j];
        reCount++;
        if(context->updatePos + reCount > context->rateInBytes-1){
            context->updatePos = 0;
            reCount = 0;
            for(x=0; x < context->rateInBytes; x++)
                context->state[x] ^= context->forUpdate[x];
            KeccakF1600_StatePermute(context->state);
        }
    }

    context->updatePos += reCount;
}

void fc_hashFinish(fc_hash_t *context, uint8_t *out){
    if(!context || !out)
        return;

    if(context->updatePos > 0){
        int j;
        for(j=0; j<context->updatePos; j++){
            context->state[j] ^= context->forUpdate[j];
        }

        context->state[context->updatePos] ^= FC_HASH_DELIMITED_SUFFIX;
        context->state[context->rateInBytes-1] ^= 0x80;
        KeccakF1600_StatePermute(context->state);
    }

    memcpy(out, context->state, context->mdLen);
    reset(context);
}


void fc_cipher_init(fc_cipher_t *context, int bitLen){
    if(!context)
        return;

    memset(context, 0, sizeof(fc_cipher_t));
    fc_hashInit(&context->ctxhash, bitLen);
    FC_RNG_INIT(&context->ctxCipherRng, bitLen);
    FC_RNG_INIT(&context->ctxIvRng, bitLen);
    FC_RNG_INIT(&context->ctxMixRng, bitLen);

    time_t ti = time(NULL);
    FC_RNG_RESEED(&context->ctxIvRng, (uint8_t*)&ti, sizeof(ti));
}

int fc_cipher_setIv(fc_cipher_t *context, uint8_t *iv, int len){
    if(!context || !iv || len < FC_CIPHER_MIN_IV)
        return 0;

    context->iv = iv;
    context->ivLen = len;
    return 1;
}

void fc_cipher_genIv(fc_cipher_t *context, uint8_t *iv, int len){
    if(!context || !iv || len < FC_CIPHER_MIN_IV)
        return;

    int i;
    for(i=0; i<len; i++)
        FC_RNG_RANDOM8(&context->ctxIvRng, iv[i]);

    context->iv = iv;
    context->ivLen = len;
}

int fc_cipher_setKey(fc_cipher_t *context, uint8_t *key, int len){
    if(!context || !key || len < FC_CIPHER_MIN_KEY)
        return 0;

    context->key = key;
    context->keyLen = len;
    return 1;
}

int fc_cipher_encrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!context || !dataIn || !dataOut || len<=0)
        return 0;

    return 1;
}

int fc_cipher_decrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!context || !dataIn || !dataOut || len<=0)
        return 0;

    return 1;
}
