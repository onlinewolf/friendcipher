#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "fccipher.h"
#include "fcspeed.h"


#define MD_BIT_LEN 384
#define MD_LEN MD_BIT_LEN/8

#define DATA_LEN 32*1024
#define IV_LEN 16
#define IV_BITLEN IV_LEN*8
#define KEY_LEN 16
#define KEY_BITLEN KEY_LEN*8

void convert(uint64_t x){
    if(x > 1024LL*1024LL*1024LL)
        printf("%llu GBps", x/(1024LL*1024LL*1024LL));
    else if(x > 1024LL*1024LL)
        printf("%llu MBps", x/(1024LL*1024LL));
    else if(x > 1024)
        printf("%llu kBps", x/(1024));
    else
        printf("%llu Bps", x);
}


int main(){

    //data
    uint8_t *data = (uint8_t*)malloc(DATA_LEN);
    int i;
    for(i=0; i<DATA_LEN; i++){
        data[i] = i;
    }

    uint8_t *dataOut = (uint8_t*)malloc(DATA_LEN);
    uint8_t *dataOut2 = (uint8_t*)malloc(DATA_LEN);

    //key
    uint8_t *key = (uint8_t*)malloc(KEY_LEN);
    for(i=0; i<KEY_LEN; i++){
        key[i] = i;
    }

    //iv
    uint8_t *iv = (uint8_t*)malloc(IV_LEN);
    for(i=0; i<IV_LEN; i++){
        iv[i] = i;
    }

    printf("(Encrypt) Data length: %d; key: %d bit; iv: %d bit\n", DATA_LEN, KEY_BITLEN, IV_BITLEN);
    printf("224 bit: "); convert(cipherSpeed(1, 224, data, dataOut, DATA_LEN, key, KEY_LEN, iv, IV_LEN)); printf("\n");
    printf("256 bit: "); convert(cipherSpeed(1, 256, data, dataOut, DATA_LEN, key, KEY_LEN, iv, IV_LEN)); printf("\n");
    printf("384 bit: "); convert(cipherSpeed(1, 384, data, dataOut2, DATA_LEN, key, KEY_LEN, iv, IV_LEN)); printf("\n");
    printf("512 bit: "); convert(cipherSpeed(1, 512, data, dataOut, DATA_LEN, key, KEY_LEN, iv, IV_LEN)); printf("\n");
    printf("\n\n");

    printf("(Decrypt) Data length: %d; key: %d bit; iv: %d bit\n", DATA_LEN, KEY_BITLEN, IV_BITLEN);
    printf("224 bit: "); convert(cipherSpeed(0, 224, data, dataOut, DATA_LEN, key, KEY_LEN, iv, IV_LEN)); printf("\n");
    printf("256 bit: "); convert(cipherSpeed(0, 256, data, dataOut, DATA_LEN, key, KEY_LEN, iv, IV_LEN)); printf("\n");
    printf("384 bit: "); convert(cipherSpeed(0, 384, dataOut2, dataOut, DATA_LEN, key, KEY_LEN, iv, IV_LEN)); printf("\n");
    printf("512 bit: "); convert(cipherSpeed(0, 512, data, dataOut2, DATA_LEN, key, KEY_LEN, iv, IV_LEN)); printf("\n");
    printf("\n\n");

    for(i=0; i<DATA_LEN; i++){
        if(data[i] != dataOut[i]){
            printf("Comparison: FAIL!\n\n");
            break;
        }
    }


/*
    fc_cipher_t cipher;
    fc_cipher_init(&cipher, MD_BIT_LEN);
    fc_cipher_setIv(&cipher, iv, IV_LEN);
    fc_cipher_setKey(&cipher, key, KEY_LEN);
    fc_cipher_encrypt(&cipher, data, dataOut, DATA_LEN);
    fc_cipher_decrypt(&cipher, dataOut, dataOut2, DATA_LEN);

    printf("encrypt: ");
    for(i=0; i<DATA_LEN; i++){
        printf("%d, ", dataOut[i]);
    }
    printf("\n\n");

    printf("decrypt: ");
    for(i=0; i<DATA_LEN; i++){
        printf("%d, ", dataOut2[i]);
    }
    printf("\n\n");

    fc_cipher_freeInContext(&cipher);
*/

    free(data);
    free(dataOut);
    free(dataOut2);
    free(key);
    free(iv);

    return 0;
}
