#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "fccipher.h"


#define MD_BIT_LEN 384
#define MD_LEN MD_BIT_LEN/8

int main(){

    //Hash
    fc_hash_t keccak;
    fc_hashInit(&keccak, MD_BIT_LEN);
    uint8_t data1[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40};
    uint8_t data2[] = {41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80};

    uint8_t mDigest[MD_LEN];
    fc_hashUpdate(&keccak, data1, 40);
    fc_hashUpdate(&keccak, data2, 40);
    fc_hashFinish(&keccak, mDigest);
    //show
    printf("Hash: ");
    int i;
    for(i=0; i<MD_LEN; i++){
        printf("%02X", mDigest[i]);
    }
    printf("\n\n");


    //RNG
    fc_rng_t rng;
    FC_RNG_INIT(&rng, MD_BIT_LEN);

    time_t ti = time(NULL);
    FC_RNG_SEED(&rng, (uint8_t*)&ti, sizeof(ti), NULL, 0);

    uint32_t random;
    FC_RNG_RANDOM8(&rng, random);
    printf("RANDOM8: %u\n", random);
    FC_RNG_RANDOM32(&rng, random);
    printf("RANDOM32: %u\n\n", random);

    FC_RNG_SEED(&rng, data1, 40, NULL, 0);
    FC_RNG_RANDOM8(&rng, random);
    printf("SRANDOM8: %u\n", random);
    FC_RNG_RANDOM32(&rng, random);
    printf("SRANDOM32: %u\n", random);

    FC_RNG_SEED(&rng, data1, 40, data2, 40);
    FC_RNG_RANDOM8(&rng, random);
    printf("S2RANDOM8: %u\n", random);
    FC_RNG_RANDOM32(&rng, random);
    printf("S2RANDOM32: %u\n", random);

    FC_RNG_RESEED(&rng, data1, 40);
    FC_RNG_RANDOM8(&rng, random);
    printf("RRANDOM8: %u\n", random);
    FC_RNG_RANDOM32(&rng, random);
    printf("RRANDOM32: %u\n", random);

    return 0;
}
