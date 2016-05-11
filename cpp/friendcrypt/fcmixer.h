#ifndef FRIENDCRYPTMIXER_H
#define FRIENDCRYPTMIXER_H
#include <cstdint>
#include "fckeccak.h"
#include "fcrng.h"

namespace friendcrypt{

/**
 * @brief The MixerWithKeccak class
 * Fisher–Yates shuffle for FriendCrypt
 */
class MixWithKeccak{
    static const long kDigestLen = 64;
    static const long kDigestBitLen = kDigestLen*8;
    static const uint8_t kMaxCrazy = 24;
    static const uint8_t kMinCrazy = 12;
    uint8_t temp_[kDigestLen];
    long listTemp_[kDigestLen];
    const uint8_t *key_;
    long keyLen_;
    const uint8_t *iv_;
    long ivLen_;
    const uint8_t* salt_;
    long saltLen_;
    Keccak hash_;
    void listMix(uint8_t* tempIn, uint8_t* dataOut, long len, Rng &rng);
    void listReverseMix(uint8_t* tempIn, uint8_t* dataOut, long len, Rng &rng);
public:

    /**
     * @brief MixWithKeccak
     * Initialization
     * @param key Key (address will be copied)
     * @param keyLen Key length (>0)
     * @param iv Initialization Vector (address will be copied)
     * @param ivLen Initialization Vector length (>0)
     * @param salt Salt (address will be copied)
     * @param saltLen Salt length (>0)
     * @throw invalidArgsException if args are incorrect
     */
    explicit MixWithKeccak(const uint8_t* key, long keyLen, const uint8_t* iv, long ivLen, const uint8_t* salt, long saltLen);

    /**
     * @brief mix
     * Fisher–Yates shuffle for FriendCrypt
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len Data length
     * @param counter Counter for CrazyMix (use: 0)
     * @return true if success
     */
    bool mix(const uint8_t* dataIn, uint8_t *dataOut, long len, uint32_t counter);

    /**
     * @brief reverseMix
     * Fisher–Yates reverse shuffle for FriendCrypt
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len Data length
     * @param counter Counter for CrazyMix (use: 0)
     * @return true if success
     */
    bool reverseMix(const uint8_t* dataIn, uint8_t* dataOut, long len, uint32_t counter);

    /**
     * @brief crazyMix
     * This method use mix() with random times
     * @param dataIn Input data (will be changed)
     * @param dataOut Output data
     * @param len Data length
     * @return true if success
     */
    bool crazyMix(const uint8_t* dataIn, uint8_t* dataOut, long len);

    /**
     * @brief crazyMix
     * This method use reverseMix() with random times
     * @param dataIn Input data (will be changed)
     * @param dataOut Output data
     * @param len Data length
     * @return true if success
     */
    bool reverseCrazyMix(const uint8_t* dataIn, uint8_t* dataOut, long len);

    virtual ~MixWithKeccak();

    //disabled
    MixWithKeccak(const MixWithKeccak& other)=delete;
    MixWithKeccak(MixWithKeccak&& other)=delete;
    MixWithKeccak& operator=(const MixWithKeccak& other)=delete;
    MixWithKeccak& operator=(MixWithKeccak&& other)=delete;
};


//"static methods"
/**
 * @brief calcBlockSize
 * Interval: [max/2, max[
 * @param x a Number
 * @param bmax Maximum block size (>0)
 * @return block size
 */
long calcBlockSize(uint32_t x, long bmax);

/**
 * @brief calcConvert
 * Convert x number to y number with params; Interval: [min, max[
 * @param x A number (>=0)
 * @param xmax Maximum x number (>0)
 * @param min Minimum y number (>=0)
 * @param max Maximum y number (>0)
 * @return y number
 */
long calcConvert(long x, double xmax, long min, long max);

/**
 * @brief calcCrazy
 * Calculate a crazy number for loop
 * @param x A random number
 * @param min Minimum number (>=1)
 * @param max Maximum number (>=1)
 * @return A number; interval: [min, max[
 */
long calcCrazy(uint32_t x, uint8_t min, uint8_t max);

}//namespace
#endif // FRIENDCRYPTMIXER_H
