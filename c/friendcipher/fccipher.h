#ifndef FCCIPHER_H
#define FCCIPHER_H
#include <stdint.h>


#define LITTLE_ENDIAN


#define FC_CIPHER_MAX_DIGEST 64
#define FC_HASH_STATE_MAX_LENGTH 200
typedef struct{
    uint8_t state[FC_HASH_STATE_MAX_LENGTH];
    uint8_t rateInBytes;
    uint8_t updatePos;
    uint8_t mdLen;
}fc_hash_t;

#define FC_RNG_MAX_DIGEST FC_CIPHER_MAX_DIGEST
typedef struct{
    fc_hash_t ctxHash;
    uint8_t seed[FC_RNG_MAX_DIGEST];
    uint8_t p;
    uint8_t mdLen;
}fc_rng_t;

typedef struct{
    uint8_t temp[FC_CIPHER_MAX_DIGEST];
    uint8_t listTemp[FC_CIPHER_MAX_DIGEST];
    fc_hash_t ctxHash;
    fc_rng_t rngIv;
    fc_rng_t rngCipher;
    fc_rng_t rngMix;
    uint8_t mdLen;
    uint8_t *key;
    uint32_t keyLen;
    uint8_t *iv;
    uint32_t ivLen;
    uint8_t init;
}fc_cipher_t;

uint8_t fc_cipherBitLenCheck(uint16_t bitLen);

int fc_cipher_init(fc_cipher_t *context, uint16_t bitLen);
int fc_cipher_setIv(fc_cipher_t *context, uint8_t *iv, uint32_t len);
int fc_cipher_genIv(fc_cipher_t *context, uint8_t *iv, uint32_t len);
int fc_cipher_setKey(fc_cipher_t *context, uint8_t *key, uint32_t len);
int fc_cipher_encrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, uint32_t len);
int fc_cipher_decrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, uint32_t len);

#endif // FCCIPHER_H
