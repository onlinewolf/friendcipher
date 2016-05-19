#ifndef FCSPEED_H_INCLUDED
#define FCSPEED_H_INCLUDED
#include <stdint.h>

#define FC_SPEED_TEST_TIMES 100

uint64_t cipherSpeed(int enc, int bitLen, const uint8_t *dataIn, uint8_t *dataOut, int len, uint8_t *key, int keyLen, uint8_t *iv, int ivLen);

#endif // FCSPEED_H_INCLUDED
