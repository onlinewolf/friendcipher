#ifndef FCKECCAK_H
#define FCKECCAK_H
#include <cstdint>

namespace friendcrypt{

//Intel x86, x86-64
#define LITTLE_ENDIAN

/**
 * @brief The Keccak class
 * (SHA-3) Keccak C++ implementation with update()
 * (Not thread safe!)
 */
class Keccak{
    uint8_t state_[200];
    long rateInBytes_;
    static const uint8_t kDelimitedSuffix_ = 0x06;
    uint8_t* forUpdate_;
    long updatePos_;
    void reset();
public:
    /**
     * @brief kMdLen_
     * Message digest byte length
     */
    const long kMdLen_;

    /**
     * @brief kMdBitLen_
     * Message digest bit length
     */
    const long kMdBitLen_;

    /**
     * @brief Keccak
     * Message digest bit length: 224, 256, 384, 512
     * @param bitLen Message digest bit length
     * @throw invalidArgsException if mdBitLen is incorrect
     */
    explicit Keccak(long bitLen);
    /**
     * @brief update
     * Add new data
     * @param data Data
     * @param len Length
     */
    void update(const uint8_t *data, long len);
    /**
     * @brief finish
     * Finish and reset
     * @param out Output array (length of array is mdLen)
     */
    void finish(uint8_t *out);

    /**
     * @brief ~Keccak
     * Delete forUpdate_
     */
    virtual ~Keccak();

    //disabled
    Keccak(const Keccak& other)=delete;
    Keccak(Keccak&& other)=delete;
    Keccak& operator=(const Keccak& other)=delete;
    Keccak& operator=(Keccak&& other)=delete;
};


//"static method"

/**
 * @brief keccakBitLenCheck
 * Message digest bit length checker
 * @param bitLen Bit length
 * @return true if Bit length is right
 */
bool keccakBitLenCheck(long bitLen);

}//namespace
#endif // FCKECCAK_H
