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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fccipher.h"
#include "3rd/KeccakP-1600/Optimized64/KeccakP-1600-SnP.h"

//---------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------
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

#if defined(_MSC_VER)
#define ROL64(a, offset) _rotl64(a, offset)
#elif defined(KeccakP1600_useSHLD)
    #define ROL64(x,N) ({ \
    register uint64_t __out; \
    register uint64_t __in = x; \
    __asm__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(N)); \
    __out; \
    })
#else
#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#endif

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
//---------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------

#define FC_HASH_DELIMITED_SUFFIX 0x06
#define FC_HASH_UPDATE_MAX_LENGTH 144

//--------------------------------------Hash
//-----------------main function
#define KECCAK_F(state) do{\
    KeccakP1600_Permute_24rounds((state));\
    }while(0)
//-----------------

int fc_cipherBitLenCheck(int bitLen){
    return (bitLen == 224 || bitLen == 256 || bitLen == 384 || bitLen == 512) ? 1 : 0;
}

#define FC_HASH_HARD_RESET(context_ptr) do{\
    (context_ptr)->updatePos = 0;\
    memset((context_ptr)->state, 0, sizeof((context_ptr)->state));\
    }while(0)

#define FC_HASH_RESET(context_ptr) do{\
    memset(&((context_ptr)->state[(context_ptr)->updatePos]), 0, sizeof((context_ptr)->state)-(context_ptr)->updatePos);\
    }while(0)


#define FC_HASH_INIT(context_ptr, bitLen) do{\
    memset((context_ptr), 0, sizeof(fc_hash_t));\
    switch(bitLen){\
        case 224:\
            (context_ptr)->rateInBytes = FC_HASH_UPDATE_MAX_LENGTH;\
        break;\
        case 256:\
            (context_ptr)->rateInBytes = 136;\
        break;\
        case 384:\
            (context_ptr)->rateInBytes = 104;\
        break;\
        case 512:\
            (context_ptr)->rateInBytes = 72;\
        break;\
        default:\
            (context_ptr)->rateInBytes = FC_HASH_UPDATE_MAX_LENGTH;\
        break;\
    }\
    (context_ptr)->mdLen = (bitLen)/8;\
    }while(0)

#define FC_HASH_UPDATE(context_ptr, data, len) do{\
    int FC_HASH_UPDATE_reCount = 0;\
    int FC_HASH_UPDATE_j;\
    uint8_t *FC_HASH_UPDATE_temp = (data);\
    for(FC_HASH_UPDATE_j=0; FC_HASH_UPDATE_j<(len); FC_HASH_UPDATE_j++){\
        (context_ptr)->state[(context_ptr)->updatePos + FC_HASH_UPDATE_reCount] ^= FC_HASH_UPDATE_temp[FC_HASH_UPDATE_j];\
        FC_HASH_UPDATE_reCount++;\
        if((context_ptr)->updatePos + FC_HASH_UPDATE_reCount > (context_ptr)->rateInBytes-1){\
            (context_ptr)->updatePos = 0;\
            FC_HASH_UPDATE_reCount = 0;\
            KECCAK_F((context_ptr)->state);\
        }\
    }\
    (context_ptr)->updatePos += FC_HASH_UPDATE_reCount;\
    }while(0)

#define FC_HASH_FINISH(context_ptr, out) do{\
    if((context_ptr)->updatePos > 0){\
        (context_ptr)->state[(context_ptr)->updatePos] ^= FC_HASH_DELIMITED_SUFFIX;\
        (context_ptr)->state[(context_ptr)->rateInBytes-1] ^= 0x80;\
        KECCAK_F((context_ptr)->state);\
    }\
    memcpy((out), (context_ptr)->state, (context_ptr)->mdLen);\
    FC_HASH_HARD_RESET((context_ptr));\
    }while(0)


#define FC_HASH_FINISH_AND_PAUSE(context_ptr) do{\
    if((context_ptr)->updatePos > 0){\
        (context_ptr)->state[(context_ptr)->updatePos] ^= FC_HASH_DELIMITED_SUFFIX;\
        (context_ptr)->state[(context_ptr)->rateInBytes-1] ^= 0x80;\
        KECCAK_F((context_ptr)->state);\
    }\
    (context_ptr)->updatePos = (context_ptr)->mdLen;\
    FC_HASH_RESET((context_ptr));\
    }while(0)


//--------------------------------------RNG

#define FC_RNG_INIT(ptr_context, bitLen) do{ \
    (ptr_context)->mdLen = (bitLen)/8;\
    (ptr_context)->p = 0;\
    FC_HASH_INIT(&((ptr_context)->ctxHash), (bitLen));\
    }while(0)

#define FC_RNG_SEED(ptr_context, ptr_seed, seedLen, ptr_salt, saltLen) do{\
    FC_HASH_HARD_RESET(&((ptr_context)->ctxHash));\
    FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_seed), (seedLen));\
    if((ptr_salt) && (saltLen) > 0){\
        FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_salt), (saltLen));\
    }\
    FC_HASH_FINISH(&((ptr_context)->ctxHash), (ptr_context)->seed);\
    FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_context)->seed, (ptr_context)->mdLen);\
    FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_context)->seed, (ptr_context)->mdLen);\
    FC_HASH_FINISH_AND_PAUSE(&((ptr_context)->ctxHash));\
    (ptr_context)->p = 0;\
    }while(0)

#define FC_RNG_RESEED(ptr_context, ptr_seed, seedLen) do{\
    FC_HASH_HARD_RESET(&((ptr_context)->ctxHash));\
    FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_context)->seed, (ptr_context)->mdLen);\
    FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_seed), (seedLen));\
    FC_HASH_FINISH(&((ptr_context)->ctxHash), (ptr_context)->seed);\
    FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_context)->seed, (ptr_context)->mdLen);\
    FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_context)->seed, (ptr_context)->mdLen);\
    FC_HASH_FINISH_AND_PAUSE(&((ptr_context)->ctxHash));\
    (ptr_context)->p = 0;\
    }while(0)

#define FC_RNG_CHECK(ptr_context) do{\
    if((ptr_context)->p >= (ptr_context)->mdLen){\
        FC_HASH_UPDATE(&((ptr_context)->ctxHash), (ptr_context)->seed, (ptr_context)->mdLen);\
        FC_HASH_FINISH_AND_PAUSE(&((ptr_context)->ctxHash));\
        (ptr_context)->p = 0;\
    }\
    }while(0)

#define FC_RNG_GET8(ptr_context) ((&((ptr_context)->ctxHash))->state[(ptr_context)->p++])

#define FC_RNG_RANDOM8(ptr_context, returnVal) do{\
    FC_RNG_CHECK(ptr_context);\
    (returnVal) = FC_RNG_GET8(ptr_context);\
    }while(0)

#define FC_RNG_RANDOM32(ptr_context, returnVal) do{\
    uint32_t FC_RNG_temp;\
    uint8_t *FC_RNG_t = (uint8_t *)&FC_RNG_temp;\
    int FC_RNG_counter;\
    for(FC_RNG_counter=0; FC_RNG_counter<4; FC_RNG_counter++){\
        FC_RNG_RANDOM8((ptr_context), FC_RNG_t[FC_RNG_counter]);\
    }\
    (returnVal) = FC_RNG_temp;\
    }while(0)


//--------------------------------------cipher
#define FC_CIPHER_MIN_KEY 16
#define FC_CIPHER_MIN_IV FC_CIPHER_MIN_KEY

int fc_cipher_init(fc_cipher_t *context, int bitLen){
    if(!context)
        return 0;

    if(!fc_cipherBitLenCheck(bitLen)){
        context->init = 0;
        return 0;
    }

    memset(context, 0, sizeof(fc_cipher_t));

    FC_HASH_INIT(&context->ctxHash, bitLen);
    FC_RNG_INIT(&context->rngCipher, bitLen);
    FC_RNG_INIT(&context->rngIv, bitLen);
    FC_RNG_INIT(&context->rngMix, bitLen);

    time_t ti = time(NULL);
    FC_RNG_RESEED(&context->rngIv, (uint8_t*)&ti, sizeof(ti));

    context->mdLen = bitLen/8;
    context->init = 1;
    return 1;
}

int fc_cipher_setIv(fc_cipher_t *context, uint8_t *iv, int len){
    if(!context || !iv || len < FC_CIPHER_MIN_IV || !context->init)
        return 0;

    context->iv = iv;
    context->ivLen = len;
    return 1;
}

int fc_cipher_genIv(fc_cipher_t *context, uint8_t *iv, int len){
    if(!context || !iv || len < FC_CIPHER_MIN_IV || !context->init)
        return 0;

    int i;
    for(i=0; i<len; i++)
        FC_RNG_RANDOM8(&context->rngIv, iv[i]);

    context->iv = iv;
    context->ivLen = len;
    return 1;
}

int fc_cipher_setKey(fc_cipher_t *context, uint8_t *key, int len){
    if(!context || !key || len < FC_CIPHER_MIN_KEY || !context->init)
        return 0;

    context->key = key;
    context->keyLen = len;
    return 1;
}

#define MIX(ctxRng, tempIn, dataOut, len) do{\
    uint8_t MIX_counter = 0;\
    uint8_t MIX_mlen = (len);\
    uint8_t MIX_random;\
    for(; MIX_counter<(len); MIX_counter++, MIX_mlen--){\
        FC_RNG_CHECK((ctxRng));\
        MIX_random = FC_RNG_GET8((ctxRng)) % MIX_mlen;\
        (dataOut)[MIX_counter] = (tempIn)[MIX_random];\
        (tempIn)[MIX_random] = (tempIn)[MIX_mlen-1];\
    }}while(0)

#define REVERSE_MIX(ptr_context, ctxRng, tempIn, dataOut, len) do{\
    uint8_t REVERSE_MIX_counter = 0;\
    for(; REVERSE_MIX_counter<(len); REVERSE_MIX_counter++){\
        FC_RNG_CHECK(&(ptr_context)->rngCipher);\
        (ptr_context)->xorTemp[REVERSE_MIX_counter] = FC_RNG_GET8(&(ptr_context)->rngCipher);\
        (ptr_context)->listTemp[REVERSE_MIX_counter] = REVERSE_MIX_counter;\
    }\
    uint8_t REVERSE_MIX_mlen = (len);\
    int REVERSE_MIX_realPosition = 0;\
    uint8_t REVERSE_MIX_random;\
    for(REVERSE_MIX_counter=0; REVERSE_MIX_counter<(len); REVERSE_MIX_counter++, REVERSE_MIX_mlen--){\
        FC_RNG_CHECK((ctxRng));\
        REVERSE_MIX_random = FC_RNG_GET8((ctxRng)) % REVERSE_MIX_mlen;\
        REVERSE_MIX_realPosition = (ptr_context)->listTemp[REVERSE_MIX_random];\
        (dataOut)[REVERSE_MIX_realPosition] = ((tempIn)[REVERSE_MIX_counter]) ^ ((ptr_context)->xorTemp[REVERSE_MIX_realPosition]);\
        (ptr_context)->listTemp[REVERSE_MIX_random] = (ptr_context)->listTemp[REVERSE_MIX_mlen-1];\
    }}while(0)


#define CALC_BLOCK_SIZE(random, bmax, result) do{\
    if((bmax)<=1){\
        (result) = 0;\
    }else{\
        uint8_t CALC_BLOCK_SIZE_bmin = (bmax)/2;\
        (result) = ((random) % CALC_BLOCK_SIZE_bmin) + CALC_BLOCK_SIZE_bmin;\
    }}while(0)


int fc_cipher_encrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!context || !dataIn || !dataOut || len<=0 || !context->init)
        return 0;

    FC_RNG_SEED(&context->rngMix, context->key, context->keyLen, NULL, 0);
    fc_hash_t* ptrTemp = &context->ctxHash;
    FC_HASH_HARD_RESET(ptrTemp);
    FC_HASH_UPDATE(ptrTemp, context->iv, context->ivLen);
    FC_HASH_FINISH_AND_PAUSE(ptrTemp);
    FC_RNG_RESEED(&context->rngMix, ptrTemp->state, ptrTemp->mdLen);

    FC_RNG_SEED(&context->rngCipher, context->iv, context->ivLen, context->key, context->keyLen);

    uint8_t blockLen;
    FC_RNG_CHECK(&context->rngMix);
    CALC_BLOCK_SIZE(FC_RNG_GET8(&context->rngMix), context->mdLen, blockLen);
    uint8_t reCount = 0;
    int i;
    for(i=0; i<len; i++){
        FC_RNG_CHECK(&context->rngCipher);
        context->temp[reCount] = dataIn[i] ^ FC_RNG_GET8(&context->rngCipher);
        reCount++;
        if(reCount > blockLen){
            MIX(&context->rngMix, context->temp, &dataOut[i-blockLen], reCount);
            reCount = 0;
            if(i!=(len-1)){
                FC_RNG_CHECK(&context->rngMix);
                CALC_BLOCK_SIZE(FC_RNG_GET8(&context->rngMix), context->mdLen, blockLen);
            }
        }
    }

    if(reCount!=0){
        MIX(&context->rngMix, context->temp, &dataOut[len-reCount], reCount);
    }

    return 1;
}

int fc_cipher_decrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!context || !dataIn || !dataOut || len<=0 || !context->init)
        return 0;

    FC_RNG_SEED(&context->rngMix, context->key, context->keyLen, NULL, 0);
    fc_hash_t* ptrTemp = &context->ctxHash;
    FC_HASH_HARD_RESET(ptrTemp);
    FC_HASH_UPDATE(ptrTemp, context->iv, context->ivLen);
    FC_HASH_FINISH_AND_PAUSE(ptrTemp);
    FC_RNG_RESEED(&context->rngMix, ptrTemp->state, ptrTemp->mdLen);

    FC_RNG_SEED(&context->rngCipher, context->iv, context->ivLen, context->key, context->keyLen);

    uint8_t blockLen;
    FC_RNG_CHECK(&context->rngMix);
    CALC_BLOCK_SIZE(FC_RNG_GET8(&context->rngMix), context->mdLen, blockLen);
    uint8_t reCount = 0;
    int i;
    for(i=0; i<len; i++){
        context->temp[reCount] = dataIn[i];
        reCount++;
        if(reCount > blockLen){
            REVERSE_MIX(context, &context->rngMix, context->temp, &dataOut[i-blockLen], reCount);
            reCount = 0;
            if(i!=(len-1)){
                FC_RNG_CHECK(&context->rngMix);
                CALC_BLOCK_SIZE(FC_RNG_GET8(&context->rngMix), context->mdLen, blockLen);
            }
        }
    }

    if(reCount!=0){
        REVERSE_MIX(context, &context->rngMix, context->temp, &dataOut[len-reCount], reCount);
    }

    return 1;
}
