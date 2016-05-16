#ifndef FRIENDCRYPTMIXER_H
#define FRIENDCRYPTMIXER_H
#include <cstdint>
#include "fckeccak.h"
#include "fcrng.h"

namespace friendcipher{

/**
 * @brief The MixWithRng class
 * Fisher–Yates shuffle for CryptWithRng
 * (Not thread safe!)
 */
class MixWithRng{
    uint8_t *temp_;
    int *listTemp_;
    const uint8_t *key_;
    int keyLen_;
    const uint8_t *iv_;
    int ivLen_;
    Keccak hash_;
    RngWithKeccak rng_;
    bool init_;
    void listMix(uint8_t* tempIn, uint8_t* dataOut, uint8_t len);
    void listReverseMix(uint8_t* tempIn, uint8_t* dataOut, uint8_t len);
public:
    /**
     * @brief kMdLen
     * Message digest byte length
     */
    const int kMdLen;

    /**
     * @brief kMdBitLen
     * Message digest bit length
     */
    const int kMdBitLen;

    /**
     * @brief kMaxCrazy
     * Maximum random times for crazy mix
     */
    static const uint8_t kMaxCrazy = 12;

    /**
     * @brief kMinCrazy
     * Minimum random times for crazy mix
     */
    static const uint8_t kMinCrazy = 6;

    /**
     * @brief MixWithRng
     * Fisher–Yates shuffle for CryptWithRng
     * @param bitLen Bit size of Keccak: 224, 256, 384, 512 bit
     * @throw invalidArgsException if bitLen is incorrect
     */
    explicit MixWithRng(int bitLen);

    /**
     * @brief init
     * Initialization/reset
     * @param key Key (address will be copied)
     * @param keyLen Key length (>0)
     * @param iv Initialization Vector (address will be copied)
     * @param ivLen Initialization Vector length (>0)
     * @return false if args are incorrect
     */
    bool init(const uint8_t* key, int keyLen, const uint8_t* iv, int ivLen);

    /**
     * @brief isInited
     * Mix initialization check
     * @return true if init() is called
     */
    bool isInited();

    /**
     * @brief mix
     * Fisher–Yates shuffle for CryptWithRng
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len Data length
     * @param counter Counter for CrazyMix (use: 0)
     * @return true if success
     */
    bool mix(const uint8_t* dataIn, uint8_t *dataOut, int len, uint32_t counter);

    /**
     * @brief reverseMix
     * Fisher–Yates reverse shuffle for CryptWithRng
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len Data length
     * @param counter Counter for CrazyMix (use: 0)
     * @return true if success
     */
    bool reverseMix(const uint8_t* dataIn, uint8_t* dataOut, int len, uint32_t counter);

    /**
     * @brief crazyMix
     * Poweful mix, this method use mix() with random times
     * @param dataIn Input data (will be changed)
     * @param dataOut Output data
     * @param len Data length
     * @return true if success
     */
    bool crazyMix(const uint8_t* dataIn, uint8_t* dataOut, int len);

    /**
     * @brief crazyMix
     * Poweful reverse mix, this method use reverseMix() with random times
     * @param dataIn Input data (will be changed)
     * @param dataOut Output data
     * @param len Data length
     * @return true if success
     */
    bool reverseCrazyMix(const uint8_t* dataIn, uint8_t* dataOut, int len);

    /**
     * @brief ~MixWithRng
     * Delete *temp_, *listTemp_
     */
    virtual ~MixWithRng();

    //disabled
    MixWithRng(const MixWithRng& other)=delete;
    MixWithRng(MixWithRng&& other)=delete;
    MixWithRng& operator=(const MixWithRng& other)=delete;
    MixWithRng& operator=(MixWithRng&& other)=delete;
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
int calcConvert(int x, double xmax, int min, int max);

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
