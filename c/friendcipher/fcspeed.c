#include <time.h>
#include <math.h>
#include "fccipher.h"
#include "fcspeed.h"


uint64_t hashSpeed(int bitLen, const uint8_t *dataIn, int len, uint8_t *dataOut){
    if(!fc_hashBitLenCheck(bitLen) || !dataIn || len <= 0 || !dataOut)
        return 0LL;

    fc_hash_t ctxHash;
    fc_hashInit(&ctxHash, bitLen);

    clock_t start, stop;
    clock_t total = 0;
    int i;
    for(i=0; i<FC_SPEED_TEST_TIMES; i++){
        start = clock();
        fc_hashUpdate(&ctxHash, dataIn, len);
        fc_hashFinish(&ctxHash, dataOut);
        stop = clock();
        total += stop-start;
    }

    return llround((double)len*CLOCKS_PER_SEC*FC_SPEED_TEST_TIMES/(total == 0LL ? 1LL : total));
}
uint64_t rngSpeed(int bitLen, uint8_t *key, int keyLen, uint8_t *iv, int ivLen, uint8_t *out, int outLen){
    if(!fc_hashBitLenCheck(bitLen) || !out || outLen<=0 || !key || keyLen<=0)
    return 0LL;

    fc_rng_t ctxRng;
    FC_RNG_INIT(&ctxRng, bitLen);
    FC_RNG_SEED(&ctxRng, key, keyLen, iv, ivLen);

    clock_t start, stop;
    clock_t total = 0;
    int i, x;
    for(i=0; i<FC_SPEED_TEST_TIMES; i++){
        start = clock();
        for(x=0; x<outLen; x++)
            FC_RNG_RANDOM8(&ctxRng, out[x]);
        stop = clock();
        total += stop-start;
    }

    return llround((double)outLen*CLOCKS_PER_SEC*FC_SPEED_TEST_TIMES/(total == 0LL ? 1LL : total));
}
uint64_t cipherSpeed(int enc, int bitLen, const uint8_t *dataIn, uint8_t *dataOut, int len, uint8_t *key, int keyLen, uint8_t *iv, int ivLen){
    if(!fc_hashBitLenCheck(bitLen) || !dataIn || !dataOut || len<=0 || !key || keyLen<=0)
        return 0LL;

    fc_cipher_t cipher;
    fc_cipher_init(&cipher, bitLen);
    fc_cipher_setKey(&cipher, key, keyLen);

    if(!iv || ivLen<=0)
        fc_cipher_genIv(&cipher, iv, ivLen);
    else
        fc_cipher_setIv(&cipher, iv, ivLen);

    clock_t start, stop;
    clock_t total = 0;
    int i;
    for(i=0; i<FC_SPEED_TEST_TIMES; i++){
        if(enc){
            start = clock();
            fc_cipher_encrypt(&cipher, dataIn, dataOut, len);
            stop = clock();
        }else{
            start = clock();
            fc_cipher_decrypt(&cipher, dataIn, dataOut, len);
            stop = clock();
        }
        total += stop-start;
    }

    return llround((double)len*CLOCKS_PER_SEC*FC_SPEED_TEST_TIMES/(total == 0LL ? 1LL : total));
}
