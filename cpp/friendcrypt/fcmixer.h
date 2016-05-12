#ifndef FRIENDCRYPTMIXER_H
#define FRIENDCRYPTMIXER_H
#include <cstdint>
#include "fckeccak.h"
#include "fcrng.h"

namespace friendcrypt{

/**
 * @brief The MixerWithKeccak class
 * Fisher–Yates shuffle for CryptWithKeccak with Rng
 * (Not thread safe!)
 */
class MixWithKeccak{
    uint8_t *temp_;
    long *listTemp_;
    const uint8_t *key_;
    long keyLen_;
    const uint8_t *iv_;
    long ivLen_;
    Keccak hash_;
    Rng rng_;
    bool init_;
    void listMix(uint8_t* tempIn, uint8_t* dataOut, uint8_t len);
    void listReverseMix(uint8_t* tempIn, uint8_t* dataOut, uint8_t len);
public:
    /**
     * @brief kMdLen
     * Message digest byte length
     */
    const long kMdLen;

    /**
     * @brief kMdBitLen
     * Message digest bit length
     */
    const long kMdBitLen;

    /**
     * @brief kMaxCrazy
     * Maximum random times for crazy mix
     */
    static const uint8_t kMaxCrazy = 24;

    /**
     * @brief kMinCrazy
     * Minimum random times for crazy mix
     */
    static const uint8_t kMinCrazy = 12;

    /**
     * @brief MixWithKeccak
     * Fisher–Yates shuffle for CryptWithKeccak with Rng
     * @param bitLen Bit size of Keccak: 224, 256, 384, 512 bit
     * @throw invalidArgsException if bitLen is incorrect
     */
    explicit MixWithKeccak(long bitLen);

    /**
     * @brief init
     * Initialization/reset
     * @param key Key (address will be copied)
     * @param keyLen Key length (>0)
     * @param iv Initialization Vector (address will be copied)
     * @param ivLen Initialization Vector length (>0)
     * @return false if args are incorrect
     */
    bool init(const uint8_t* key, long keyLen, const uint8_t* iv, long ivLen);

    /**
     * @brief isInited
     * Mix initialization check
     * @return true if init() is called
     */
    bool isInited();

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
     * Poweful mix, this method use mix() with random times
     * @param dataIn Input data (will be changed)
     * @param dataOut Output data
     * @param len Data length
     * @return true if success
     */
    bool crazyMix(const uint8_t* dataIn, uint8_t* dataOut, long len);

    /**
     * @brief crazyMix
     * Poweful reverse mix, this method use reverseMix() with random times
     * @param dataIn Input data (will be changed)
     * @param dataOut Output data
     * @param len Data length
     * @return true if success
     */
    bool reverseCrazyMix(const uint8_t* dataIn, uint8_t* dataOut, long len);

    /**
     * @brief ~MixWithKeccak
     * Delete *temp_, *listTemp_
     */
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
uint8_t calcBlockSize(uint8_t x, uint8_t bmax);

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
uint8_t calcCrazy(uint8_t x, uint8_t min, uint8_t max);

}//namespace
#endif // FRIENDCRYPTMIXER_H
