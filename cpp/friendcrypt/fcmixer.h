#ifndef FRIENDCRYPTMIXER_H
#define FRIENDCRYPTMIXER_H
#include <cstdint>

namespace friendcrypt{

/**
 * @brief The MixerWithKeccak class
 * Mixer for FriendCrypt.
 */
class MixWithKeccak{
    const int kSaltLen;
    const int kDigestLen;
    int tempSHKLen_;
    uint8_t *salt_;
    uint8_t *tempSHK_;//salt and hash and key
    uint8_t *digest_;
    void listMix(uint8_t* data, long start, long len, uint8_t key);
    void listReverseMix(uint8_t* data, long start, long len, uint8_t key);
public:

    /**
     * @brief MixerWithKeccak
     * Constructor
     * @param salt for keccak
     * @param len salt length
     * @param digestLen for keccak (32 or 64)
     * @throw invalidArgsException if args are incorrect
     */
    explicit MixWithKeccak(uint8_t* salt, long len, long digestLen);

    /**
     * @brief mix
     * Fisher–Yates shuffle for FriendCrypt
     * @param data crypted data
     * @param len data length
     * @param key keys
     * @param klen size (for array of keys)
     * @param bmax maximum block size
     */
    void mix(uint8_t* data, long len, uint8_t* key, long klen, long bmax);

    /**
     * @brief reverseMix
     * Fisher–Yates reverse shuffle for FriendCrypt
     * @param data crypted data
     * @param len data length
     * @param key keys
     * @param klen size (for array of keys)
     * @param bmax maximum block size
     */
    void reverseMix(uint8_t* data, long len, uint8_t* key, long klen, long bmax);

    virtual ~MixWithKeccak();

    MixWithKeccak(const MixWithKeccak& other)=delete;
    MixWithKeccak(MixWithKeccak&& other)=delete;
    MixWithKeccak& operator=(const MixWithKeccak& other)=delete;
    MixWithKeccak& operator=(MixWithKeccak&& other)=delete;
};

/**
 * @brief calcBlockSize
 * @param key a key
 * @param bmax maximum block size
 * @return block size
 */
long calcBlockSize(uint8_t key, long bmax);

/**
 * @brief calcConvert
 * Convert x number to y number with params
 * @param x number (not <0)
 * @param xmax maximum x number
 * @param min minimum y number (not <0)
 * @param max maximum y number (not <=0)
 * @return y number
 */
long calcConvert(long x, double xmax, long min, long max);

}//namespace
#endif // FRIENDCRYPTMIXER_H
