#ifndef FCKECCAK_H
#define FCKECCAK_H
#include <cstdint>

namespace friendcipher{

//Intel x86, x86-64
#define LITTLE_ENDIAN

/**
 * @brief The Hash class
 * (SHA-3) Keccak C++ implementation with update()
 * (Not thread safe!)
 */
class Hash{
    uint8_t state_[200];
    int rateInBytes_;
    static const uint8_t kDelimitedSuffix_ = 0x06;
    uint8_t* forUpdate_;
    int updatePos_;
    void reset();
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
     * @brief Hash
     * Message digest bit length: 224, 256, 384, 512
     * @param bitLen Message digest bit length
     * @throw invalidArgsException if mdBitLen is incorrect
     */
    explicit Hash(int bitLen);
    /**
     * @brief update
     * Add new data
     * @param data Data
     * @param len Length
     */
    void update(const uint8_t *data, int len);
    /**
     * @brief finish
     * Finish and reset
     * @param out Output array (length of array is mdLen)
     */
    void finish(uint8_t *out);

    /**
     * @brief ~Hash
     * Delete forUpdate_
     */
    virtual ~Hash();

    //disabled
    Hash(const Hash& other)=delete;
    Hash(Hash&& other)=delete;
    Hash& operator=(const Hash& other)=delete;
    Hash& operator=(Hash&& other)=delete;
};


//"static method"

/**
 * @brief keccakBitLenCheck
 * Message digest bit length checker
 * @param bitLen Bit length
 * @return true if Bit length is right
 */
bool keccakBitLenCheck(int bitLen);

}//namespace
#endif // FCKECCAK_H
