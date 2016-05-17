#ifndef FCCIPHER_H
#define FCCIPHER_H
#include <stdint.h>

#define FC_HASH_DELIMITED_SUFFIX 0x06
#define FC_HASH_STATE_MAX_LENGTH 200
#define FC_HASH_UPDATE_MAX_LENGTH 144
#define LITTLE_ENDIAN

typedef struct{
    uint8_t state[FC_HASH_STATE_MAX_LENGTH];
    uint8_t forUpdate[FC_HASH_UPDATE_MAX_LENGTH];
    int rateInBytes;
    int updatePos;
    int mdLen;
    int init;
}fc_hash_t;

int fc_hashBitLenCheck(int bitLen);
int fc_hashInit(fc_hash_t *context, int bitLen);
int fc_hashUpdate(fc_hash_t *context, const uint8_t *data, int len);
int fc_hashFinish(fc_hash_t *context, uint8_t *out);


#define FC_RNG_MAX_DIGEST 64

typedef struct{
    fc_hash_t ctxHash;
    uint8_t seed[FC_RNG_MAX_DIGEST];
    uint8_t randMd[FC_RNG_MAX_DIGEST];
    int p;
    int mdLen;
    int init;
}fc_rng_t;

#define FC_RNG_INIT(ptr_context, bitLen) do{ \
    (ptr_context)->mdLen = (bitLen)/8;\
    (ptr_context)->p = 0;\
    (ptr_context)->init = 0;\
    fc_hashInit(&(ptr_context)->ctxHash, (bitLen));\
    }while(0)

#define FC_RNG_SEED(ptr_context, ptr_seed, seedLen, ptr_salt, saltLen) do{\
    fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_seed), (seedLen));\
    if((ptr_salt) && (saltLen) > 0)\
        fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_salt), (saltLen));\
    fc_hashFinish(&(ptr_context)->ctxHash, (ptr_context)->seed);\
    fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_context)->seed, (ptr_context)->mdLen);\
    fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_context)->seed, (ptr_context)->mdLen);\
    fc_hashFinish(&(ptr_context)->ctxHash, (ptr_context)->randMd);\
    (ptr_context)->p = 0;\
    (ptr_context)->init = 1;\
    }while(0)

#define FC_RNG_RESEED(ptr_context, ptr_seed, seedLen) do{\
    fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_context)->seed, (ptr_context)->mdLen);\
    fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_seed), (seedLen));\
    fc_hashFinish(&(ptr_context)->ctxHash, (ptr_context)->seed);\
    fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_context)->seed, (ptr_context)->mdLen);\
    fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_context)->seed, (ptr_context)->mdLen);\
    fc_hashFinish(&(ptr_context)->ctxHash, (ptr_context)->randMd);\
    (ptr_context)->p = 0;\
    (ptr_context)->init = 1;\
    }while(0)

#define FC_RNG_RANDOM8(ptr_context, returnVal) do{\
    if(!(ptr_context)->init){\
        (returnVal) = 0;\
    }else{\
        if((ptr_context)->p >= (ptr_context)->mdLen){\
            fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_context)->randMd, (ptr_context)->mdLen);\
            fc_hashUpdate(&(ptr_context)->ctxHash, (ptr_context)->seed, (ptr_context)->mdLen);\
            fc_hashFinish(&(ptr_context)->ctxHash, (ptr_context)->randMd);\
            (ptr_context)->p = 0;\
        }\
        (returnVal) = (ptr_context)->randMd[(ptr_context)->p];\
        (ptr_context)->p++;\
    }}while(0)

#define FC_RNG_RANDOM32(ptr_context, returnVal) do{\
    if(!(ptr_context)->init){\
        (returnVal) = 0;\
    }else{\
        uint32_t FC_RNG_temp;\
        uint8_t *FC_RNG_t = (uint8_t *)&FC_RNG_temp;\
        int FC_RNG_counter;\
        for(FC_RNG_counter=0; i<4; FC_RNG_counter++)\
            FC_RNG_RANDOM8(ptr_context, FC_RNG_t[FC_RNG_counter]);\
        (returnVal) = FC_RNG_temp;\
    }}while(0)


#define FC_CIPHER_MAX_DIGEST FC_RNG_MAX_DIGEST
#define FC_CIPHER_MIN_KEY 16
#define FC_CIPHER_MIN_IV FC_CIPHER_MIN_KEY

typedef struct{
    uint8_t temp[FC_CIPHER_MAX_DIGEST];
    int listTemp[FC_CIPHER_MAX_DIGEST];
    uint8_t xorTemp[FC_CIPHER_MAX_DIGEST];
    fc_hash_t ctxhash;
    fc_rng_t ctxIvRng;
    fc_rng_t ctxCipherRng;
    fc_rng_t ctxMixRng;
    int mdLen;
    uint8_t *key;
    int keyLen;
    uint8_t *iv;
    int ivLen;
    int init;
}fc_cipher_t;


int fc_cipher_init(fc_cipher_t *context, int bitLen);
int fc_cipher_setIv(fc_cipher_t *context, uint8_t *iv, int len);
int fc_cipher_genIv(fc_cipher_t *context, uint8_t *iv, int len);
int fc_cipher_setKey(fc_cipher_t *context, uint8_t *key, int len);
int fc_cipher_encrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len);
int fc_cipher_decrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len);

#endif // FCCIPHER_H
