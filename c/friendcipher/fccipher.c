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

#define FC_HASH_DELIMITED_SUFFIX 0x06
#define FC_HASH_UPDATE_MAX_LENGTH 144

//--------------------------------------Hash
//-----------------main function----------------
#define KECCAK_F(state) do{\
    KeccakP1600_Permute_24rounds((state));\
    }while(0)
//----------------------------------------------

uint8_t fc_cipherBitLenCheck(uint16_t bitLen){
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
    uint8_t FC_HASH_UPDATE_reCount = 0;\
    uint32_t FC_HASH_UPDATE_j;\
    uint8_t *FC_HASH_UPDATE_temp = (data);\
    uint8_t *FC_HASH_UPDATE_tempState = (context_ptr)->state;\
    for(FC_HASH_UPDATE_j=0; FC_HASH_UPDATE_j<(len); FC_HASH_UPDATE_j++){\
        FC_HASH_UPDATE_tempState[(context_ptr)->updatePos + FC_HASH_UPDATE_reCount] ^= FC_HASH_UPDATE_temp[FC_HASH_UPDATE_j];\
        FC_HASH_UPDATE_reCount++;\
        if((context_ptr)->updatePos + FC_HASH_UPDATE_reCount >= (context_ptr)->rateInBytes){\
            (context_ptr)->updatePos = 0;\
            FC_HASH_UPDATE_reCount = 0;\
            KECCAK_F(FC_HASH_UPDATE_tempState);\
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
    uint8_t *FC_RNG_t = (uint8_t *)&(returnVal);\
    FC_RNG_RANDOM8((ptr_context), FC_RNG_t[0]);\
    FC_RNG_RANDOM8((ptr_context), FC_RNG_t[1]);\
    FC_RNG_RANDOM8((ptr_context), FC_RNG_t[2]);\
    FC_RNG_RANDOM8((ptr_context), FC_RNG_t[3]);\
    }while(0)


//--------------------------------------cipher
#define FC_CIPHER_MIN_KEY 16
#define FC_CIPHER_MIN_IV FC_CIPHER_MIN_KEY

int fc_cipher_init(fc_cipher_t *context, uint16_t bitLen){
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

int fc_cipher_setIv(fc_cipher_t *context, uint8_t *iv, uint32_t len){
    if(!context || !iv || len < FC_CIPHER_MIN_IV || !context->init)
        return 0;

    context->iv = iv;
    context->ivLen = len;
    return 1;
}

int fc_cipher_genIv(fc_cipher_t *context, uint8_t *iv, uint32_t len){
    if(!context || !iv || len < FC_CIPHER_MIN_IV || !context->init)
        return 0;

    uint32_t i;
    for(i=0; i<len; i++)
        FC_RNG_RANDOM8(&context->rngIv, iv[i]);

    context->iv = iv;
    context->ivLen = len;
    return 1;
}

int fc_cipher_setKey(fc_cipher_t *context, uint8_t *key, uint32_t len){
    if(!context || !key || len < FC_CIPHER_MIN_KEY || !context->init)
        return 0;

    context->key = key;
    context->keyLen = len;
    return 1;
}

#define MIX_DEF_VARS \
    uint8_t MIX_counter;\
    uint8_t MIX_mlen;\
    uint8_t MIX_random;

#define MIX(ctxRng, tempIn, dataOut, len) do{\
    MIX_mlen = (len);\
    for(MIX_counter = 0; MIX_counter<(len); MIX_counter++, MIX_mlen--){\
        FC_RNG_CHECK((ctxRng));\
        MIX_random = FC_RNG_GET8((ctxRng)) % MIX_mlen;\
        (dataOut)[MIX_counter] = (tempIn)[MIX_random];\
        (tempIn)[MIX_random] = (tempIn)[MIX_mlen-1];\
    }}while(0)

#define REVERSE_MIX_DEF_VARS(ptr_context) \
    uint8_t REVERSE_MIX_counter;\
    uint8_t *REVERSE_MIX_temp = (ptr_context)->temp;\
    uint8_t *REVERSE_MIX_listTemp = (ptr_context)->listTemp;\
    fc_rng_t *REVERSE_MIX_tempRng = &(ptr_context)->rngCipher;\
    uint8_t REVERSE_MIX_mlen;\
    uint8_t REVERSE_MIX_realPosition;\
    uint8_t REVERSE_MIX_random;

#define REVERSE_MIX(ctxRng, tempIn, dataOut, len) do{\
    for(REVERSE_MIX_counter = 0; REVERSE_MIX_counter<(len); REVERSE_MIX_counter++){\
        FC_RNG_CHECK(REVERSE_MIX_tempRng);\
        REVERSE_MIX_temp[REVERSE_MIX_counter] = FC_RNG_GET8(REVERSE_MIX_tempRng);\
        REVERSE_MIX_listTemp[REVERSE_MIX_counter] = REVERSE_MIX_counter;\
    }\
    REVERSE_MIX_mlen = (len);\
    for(REVERSE_MIX_counter=0; REVERSE_MIX_counter<(len); REVERSE_MIX_counter++, REVERSE_MIX_mlen--){\
        FC_RNG_CHECK((ctxRng));\
        REVERSE_MIX_random = FC_RNG_GET8((ctxRng)) % REVERSE_MIX_mlen;\
        REVERSE_MIX_realPosition = REVERSE_MIX_listTemp[REVERSE_MIX_random];\
        (dataOut)[REVERSE_MIX_realPosition] = ((tempIn)[REVERSE_MIX_counter]) ^ (REVERSE_MIX_temp[REVERSE_MIX_realPosition]);\
        REVERSE_MIX_listTemp[REVERSE_MIX_random] = REVERSE_MIX_listTemp[REVERSE_MIX_mlen-1];\
    }}while(0)


#define CALC_BLOCK_SIZE(random, bmax, result) do{\
    if((bmax)<=1){\
        (result) = 0;\
    }else{\
        uint8_t CALC_BLOCK_SIZE_bmin = (bmax)/2;\
        (result) = ((random) % CALC_BLOCK_SIZE_bmin) + CALC_BLOCK_SIZE_bmin;\
    }}while(0)


int fc_cipher_encrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, uint32_t len){
    if(!context || !dataIn || !dataOut || len<=0 || !context->init)
        return 0;

    fc_rng_t *rngCTemp = &context->rngCipher;
    fc_rng_t *rngMTemp = &context->rngMix;

    FC_RNG_SEED(rngMTemp, context->key, context->keyLen, NULL, 0);
    fc_hash_t *ptrTemp = &context->ctxHash;
    FC_HASH_HARD_RESET(ptrTemp);
    FC_HASH_UPDATE(ptrTemp, context->iv, context->ivLen);
    FC_HASH_FINISH_AND_PAUSE(ptrTemp);
    FC_RNG_RESEED(rngMTemp, ptrTemp->state, ptrTemp->mdLen);

    FC_RNG_SEED(rngCTemp, context->iv, context->ivLen, context->key, context->keyLen);

    uint8_t blockLen;
    FC_RNG_CHECK(rngMTemp);
    uint8_t mdLen = context->mdLen;
    CALC_BLOCK_SIZE(FC_RNG_GET8(rngMTemp), mdLen, blockLen);
    uint8_t reCount = 0;
    uint32_t i;
    uint8_t *contextTemp = context->temp;
    uint8_t *outPtr;
    MIX_DEF_VARS;
    for(i=0; i<len; i++){
        FC_RNG_CHECK(rngCTemp);
        contextTemp[reCount] = dataIn[i] ^ FC_RNG_GET8(rngCTemp);
        reCount++;
        if(reCount > blockLen){
            outPtr = &dataOut[i-blockLen];
            MIX(rngMTemp, contextTemp, outPtr, reCount);
            reCount = 0;
            if(i!=(len-1)){
                FC_RNG_CHECK(rngMTemp);
                CALC_BLOCK_SIZE(FC_RNG_GET8(rngMTemp), mdLen, blockLen);
            }
        }
    }

    if(reCount!=0){
        outPtr = &dataOut[len-reCount];
        MIX(rngMTemp, contextTemp, outPtr, reCount);
    }

    return 1;
}

int fc_cipher_decrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, uint32_t len){
    if(!context || !dataIn || !dataOut || len<=0 || !context->init)
        return 0;

    fc_rng_t *rngCTemp = &context->rngCipher;
    fc_rng_t *rngMTemp = &context->rngMix;
    FC_RNG_SEED(rngMTemp, context->key, context->keyLen, NULL, 0);
    fc_hash_t* ptrTemp = &context->ctxHash;
    FC_HASH_HARD_RESET(ptrTemp);
    FC_HASH_UPDATE(ptrTemp, context->iv, context->ivLen);
    FC_HASH_FINISH_AND_PAUSE(ptrTemp);
    FC_RNG_RESEED(rngMTemp, ptrTemp->state, ptrTemp->mdLen);

    FC_RNG_SEED(rngCTemp, context->iv, context->ivLen, context->key, context->keyLen);

    uint8_t blockLen;
    FC_RNG_CHECK(rngMTemp);
    uint8_t mdLen = context->mdLen;
    CALC_BLOCK_SIZE(FC_RNG_GET8(rngMTemp), mdLen, blockLen);
    uint8_t reCount = 0;
    uint32_t i;
    const uint8_t *inPtr;
    uint8_t *outPtr;
    uint8_t calc;
    REVERSE_MIX_DEF_VARS(context);
    for(i=0; i<len; i++){
        if(len-i > blockLen){
            inPtr = &dataIn[i];
            outPtr = &dataOut[i];
            calc = blockLen+1;
            REVERSE_MIX(rngMTemp, inPtr, outPtr, calc);
            i += blockLen;
            if(i!=(len-1)){
                FC_RNG_CHECK(rngMTemp);
                CALC_BLOCK_SIZE(FC_RNG_GET8(rngMTemp), mdLen, blockLen);
            }
        }else{
            reCount++;
        }
    }

    if(reCount!=0){
        inPtr = &dataIn[len-reCount];
        outPtr = &dataOut[len-reCount];
        REVERSE_MIX(rngMTemp, inPtr, outPtr, reCount);
    }

    return 1;
}
