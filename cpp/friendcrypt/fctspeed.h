#ifndef SPEED_H
#define SPEED_H
#include <cstdint>
#include <chrono>

namespace friendcrypt{
namespace test{

/**
 * @brief kSpeedTestTimes
 * Number of tests
 */
static const int kSpeedTestTimes = 50;

/**
 * @brief keccakSpeed
 * Keccak speed test
 * @param bitLen Message digest bit length
 * @param dataIn Input data
 * @param len Length
 * @param dataOut Output data
 * @return Byte/s
 */
uint64_t keccakSpeed(int bitLen, const uint8_t *dataIn, int len, uint8_t *dataOut);

/**
 * @brief rngSpeed
 * Rng speed test
 * @param bitLen Message digest bit length
 * @param key Key
 * @param keyLen Key length
 * @param iv IV
 * @param ivLen IV length
 * @param out Output data
 * @param outLen Output length
 * @return Byte/s
 */
uint64_t rngSpeed(int bitLen, const uint8_t *key, int keyLen, const uint8_t *iv, int ivLen, uint8_t *out, int outLen);

/**
 * @brief mixSpeed
 * MixWithKeccak speed test
 * @param enc Encrypt/decrypt mode
 * @param crazy Crazy/normal mode
 * @param bitLen Message digest bit length
 * @param dataIn Input data
 * @param dataOut Output data
 * @param len Length
 * @param key Key
 * @param keyLen Key length
 * @param iv IV
 * @param ivLen IV length
 * @return Byte/s
 */
uint64_t mixSpeed(bool enc, bool crazy, int bitLen, const uint8_t *dataIn, uint8_t *dataOut, int len, const uint8_t *key, int keyLen, const uint8_t *iv, int ivLen);

/**
 * @brief cryptSpeed
 * CryptWithKeccak speed test
 * @param enc Encrypt/decrypt mode
 * @param crazy Crazy/normal mode
 * @param bitLen Message digest bit length
 * @param dataIn Input data
 * @param dataOut Output data
 * @param len Length
 * @param key Key
 * @param keyLen Key length
 * @param iv IV (optional)
 * @param ivLen IV length (optional)
 * @return Byte/s
 */
uint64_t cryptSpeed(bool enc, bool crazy, int bitLen, const uint8_t *dataIn, uint8_t *dataOut, int len, const uint8_t *key, int keyLen, const uint8_t *iv, int ivLen);

}//namespace
}//namespace
#endif // SPEED_H
