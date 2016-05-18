#ifndef FCCIPHER_H
#define FCCIPHER_H
#include <stdint.h>


#define LITTLE_ENDIAN

#define FC_CIPHER_MAX_DIGEST 64

typedef struct{
    uint8_t temp[FC_CIPHER_MAX_DIGEST];
    int listTemp[FC_CIPHER_MAX_DIGEST];
    uint8_t xorTemp[FC_CIPHER_MAX_DIGEST];
    void* ctxHash;
    void* rngIv;
    void* rngCipher;
    void* rngMix;
    int mdLen;
    uint8_t *key;
    int keyLen;
    uint8_t *iv;
    int ivLen;
    int init;
}fc_cipher_t;

int fc_cipherBitLenCheck(int bitLen);

int fc_cipher_init(fc_cipher_t *context, int bitLen);
int fc_cipher_setIv(fc_cipher_t *context, uint8_t *iv, int len);
int fc_cipher_genIv(fc_cipher_t *context, uint8_t *iv, int len);
int fc_cipher_setKey(fc_cipher_t *context, uint8_t *key, int len);
int fc_cipher_encrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len);
int fc_cipher_decrypt(fc_cipher_t *context, const uint8_t *dataIn, uint8_t *dataOut, int len);
void fc_cipher_freeInContext(fc_cipher_t *context);

#endif // FCCIPHER_H
