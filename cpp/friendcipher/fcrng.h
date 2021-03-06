#ifndef FCRNG_H
#define FCRNG_H
#include <cstdint>
#include <fchash.h>

namespace friendcipher{

/**
 * @brief The RngWithHash class
 * Powerful Random Number Generator with Keccak
 * (Not thread safe!)
 */
class RngWithHash{
    Hash hash_;
    uint8_t *seed_;
    uint8_t *randMd_;
    uint8_t p_;
    bool init_;
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
     * @brief RngWithHash
     * Random Number Generator with Hash
     * @param bitLen Bit size of Keccak: 224, 256, 384, 512 bit
     * @throw invalidArgsException if bitLen is invalid
     */
    explicit RngWithHash(int bitLen);

    /**
     * @brief init
     * Initialization/reset with seed (salt is optional)
     * @param seed Seed data
     * @param seedLen Seed data length
     * @param salt Salt (can be nullptr)
     * @param saltLen Salt length (can be 0)
     * @return false if seed is nullptr or seedLen is <=0
     */
    bool init(const uint8_t *seed, int seedLen, const uint8_t *salt, int saltLen);

    /**
     * @brief isInit
     * Rng initialization check
     * @return true if init() is called
     */
    bool isInited();

    /**
     * @brief reSeed
     * Create new seed with last seed (the last seed is unkown if init() isn't called)
     * @param seed New seed
     * @param seedLen New seed length
     * @return false if seed is nullptr or seedLen is <=0
     */
    bool reSeed(const uint8_t *seed, int seedLen);

    /**
     * @brief random8bit
     * 8 bit random number
     * @return random number
     */
    uint8_t random8bit();

    /**
     * @brief random32bit
     * 32 bit random number
     * @return random number
     */
    uint32_t random32bit();

    /**
     * @brief ~RngWithHash
     * Delete *seed_, *randMd_
     */
    virtual ~RngWithHash();

    //disabled
    RngWithHash(const RngWithHash& other)=delete;
    RngWithHash(RngWithHash&& other)=delete;
    RngWithHash& operator=(const RngWithHash& other)=delete;
    RngWithHash& operator=(RngWithHash&& other)=delete;
};

}//namespace
#endif // FCRNG_H
