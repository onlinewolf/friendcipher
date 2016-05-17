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
#include "3rd/KeccakP-1600/Optimized64/KeccakP-1600-SnP.h"
#include "fccipher.h"

static void keccakF(void *state){
    KeccakP1600_Permute_24rounds(state);
}

int fc_hashBitLenCheck(int bitLen){
    return (bitLen == 224 || bitLen == 256 || bitLen == 384 || bitLen == 512) ? 1 : 0;
}

static void reset(fc_hash_t *context){
    if(!context)
        return;

    context->updatePos = 0;
    memset(context->state, 0, sizeof(context->state));
}

int fc_hashInit(fc_hash_t *context, int bitLen){
    if(!context)
        return 0;

    if(!fc_hashBitLenCheck(bitLen)){
        context->init = 0;
        return 0;
    }


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
    context->init = 1;
    return 1;
}

int fc_hashUpdate(fc_hash_t *context, const uint8_t *data, int len){
    if(!context || !data || len <= 0 || !context->init)
        return 0;

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
            keccakF(context->state);
        }
    }

    context->updatePos += reCount;
    return 1;
}

int fc_hashFinish(fc_hash_t *context, uint8_t *out){
    if(!context || !out || !context->init)
        return 0;

    if(context->updatePos > 0){
        int j;
        for(j=0; j<context->updatePos; j++){
            context->state[j] ^= context->forUpdate[j];
        }

        context->state[context->updatePos] ^= FC_HASH_DELIMITED_SUFFIX;
        context->state[context->rateInBytes-1] ^= 0x80;
        keccakF(context->state);
    }

    memcpy(out, context->state, context->mdLen);
    reset(context);
    return 1;
}


int fc_cipher_init(fc_cipher_t *context, int bitLen){
    if(!context)
        return 0;

    if(!fc_hashBitLenCheck(bitLen)){
        context->init = 0;
        return 0;
    }

    memset(context, 0, sizeof(fc_cipher_t));
    fc_hashInit(&context->ctxhash, bitLen);
    FC_RNG_INIT(&context->ctxCipherRng, bitLen);
    FC_RNG_INIT(&context->ctxIvRng, bitLen);
    FC_RNG_INIT(&context->ctxMixRng, bitLen);

    time_t ti = time(NULL);
    FC_RNG_RESEED(&context->ctxIvRng, (uint8_t*)&ti, sizeof(ti));

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
        FC_RNG_RANDOM8(&context->ctxIvRng, iv[i]);

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
    for(; MIX_counter<(len); MIX_counter++, MIX_mlen--){\
        uint8_t MIX_random;\
        FC_RNG_RANDOM8((ctxRng), MIX_random);\
        MIX_random = MIX_random % MIX_mlen;\
        (dataOut)[MIX_counter] = (tempIn)[MIX_random];\
        (tempIn)[MIX_random] = (tempIn)[MIX_mlen-1];\
    }}while(0)

#define REVERSE_MIX(ptr_context, ctxRng, tempIn, dataOut, len) do{\
    uint8_t REVERSE_MIX_counter = 0;\
    for(; REVERSE_MIX_counter<(len); REVERSE_MIX_counter++){\
        FC_RNG_RANDOM8(&(ptr_context)->ctxCipherRng, (ptr_context)->xorTemp[REVERSE_MIX_counter]);\
        (ptr_context)->listTemp[REVERSE_MIX_counter] = REVERSE_MIX_counter;\
    }\
    uint8_t REVERSE_MIX_mlen = (len);\
    int REVERSE_MIX_realPosition = 0;\
    for(REVERSE_MIX_counter=0; REVERSE_MIX_counter<(len); REVERSE_MIX_counter++, REVERSE_MIX_mlen--){\
        uint8_t REVERSE_MIX_random;\
        FC_RNG_RANDOM8((ctxRng), REVERSE_MIX_random);\
        REVERSE_MIX_random = REVERSE_MIX_random % REVERSE_MIX_mlen;\
        REVERSE_MIX_realPosition = (ptr_context)->listTemp[REVERSE_MIX_random];\
        (dataOut)[REVERSE_MIX_realPosition] = ((tempIn)[REVERSE_MIX_counter]) ^ ((ptr_context)->xorTemp[REVERSE_MIX_realPosition]);\
        (ptr_context)->listTemp[REVERSE_MIX_random] = (ptr_context)->listTemp[REVERSE_MIX_mlen-1];\
    }}while(0)


#define CALC_BLOCK_SIZE(random, bmax, result) do{\
    if((bmax)<=1){\
        (result) = 0;\
    }else{\
        uint8_t CALC_BLOCK_SIZE_bmin = (bmax)/2;\
        (random) = (random) % CALC_BLOCK_SIZE_bmin;\
        (result) = (random) + CALC_BLOCK_SIZE_bmin;\
    }}while(0)


int fc_cipher_encrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!context || !dataIn || !dataOut || len<=0 || !context->init)
        return 0;

    FC_RNG_SEED(&context->ctxMixRng, context->key, context->keyLen, NULL, 0);
    fc_hashUpdate(&context->ctxhash, context->iv, context->ivLen);
    fc_hashFinish(&context->ctxhash, context->temp);
    FC_RNG_RESEED(&context->ctxMixRng, context->temp, context->mdLen);

    FC_RNG_SEED(&context->ctxCipherRng, context->iv, context->ivLen, context->key, context->keyLen);

    uint8_t randomMix;
    uint8_t randomCipher;
    FC_RNG_RANDOM8(&context->ctxMixRng, randomMix);
    uint8_t blockLen;
    CALC_BLOCK_SIZE(randomMix, context->mdLen, blockLen);
    uint8_t reCount = 0;
    int i;
    for(i=0; i<len; i++){
        FC_RNG_RANDOM8(&context->ctxCipherRng, randomCipher);
        context->temp[reCount] = dataIn[i] ^ randomCipher;
        reCount++;
        if(reCount > blockLen){
            MIX(&context->ctxMixRng, context->temp, &dataOut[i-blockLen], reCount);
            reCount = 0;
            if(i!=(len-1)){
                FC_RNG_RANDOM8(&context->ctxMixRng, randomMix);
                CALC_BLOCK_SIZE(randomMix, context->mdLen, blockLen);
            }
        }
    }

    if(reCount!=0){
        MIX(&context->ctxMixRng, context->temp, &dataOut[len-reCount], reCount);
    }

    return 1;
}

int fc_cipher_decrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!context || !dataIn || !dataOut || len<=0 || !context->init)
        return 0;

    FC_RNG_SEED(&context->ctxMixRng, context->key, context->keyLen, NULL, 0);
    fc_hashUpdate(&context->ctxhash, context->iv, context->ivLen);
    fc_hashFinish(&context->ctxhash, context->temp);
    FC_RNG_RESEED(&context->ctxMixRng, context->temp, context->mdLen);

    FC_RNG_SEED(&context->ctxCipherRng, context->iv, context->ivLen, context->key, context->keyLen);

    uint8_t random;
    FC_RNG_RANDOM8(&context->ctxMixRng, random);
    uint8_t blockLen;
    CALC_BLOCK_SIZE(random, context->mdLen, blockLen);
    uint8_t reCount = 0;
    int i;
    for(i=0; i<len; i++){
        context->temp[reCount] = dataIn[i];
        reCount++;
        if(reCount > blockLen){
            REVERSE_MIX(context, &context->ctxMixRng, context->temp, &dataOut[i-blockLen], reCount);
            reCount = 0;
            if(i!=(len-1)){
                FC_RNG_RANDOM8(&context->ctxMixRng, random);
                CALC_BLOCK_SIZE(random, context->mdLen, blockLen);
            }
        }
    }

    if(reCount!=0){
        REVERSE_MIX(context, &context->ctxMixRng, context->temp, &dataOut[len-reCount], reCount);
    }

    return 1;
}
