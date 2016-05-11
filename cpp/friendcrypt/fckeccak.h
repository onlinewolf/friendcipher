#ifndef FCKECCAK_H
#define FCKECCAK_H
#include <cstdint>

namespace friendcrypt{

//Intel x86, x86-64
#define LITTLE_ENDIAN

/**
 * @brief The Keccak class
 * 3rd Keccak C++ implementation
 */
class Keccak{
    uint8_t state_[200];
    uint32_t rateInBytes_;
    const uint8_t kDelimitedSuffix_ = 0x06;
    uint8_t* forUpdate_;
    uint32_t updatePos_;
    uint32_t mdLen_;
    void reset();
public:
    /**
     * @brief Keccak
     * Message digest bit length: 224, 256, 384, 512
     * @param mdBitLen bit length
     * @throw invalidArgsException if mdBitLen is incorrect
     */
    explicit Keccak(int mdBitLen);
    /**
     * @brief update
     * Add new data
     * @param data
     * @param len length
     */
    void update(const uint8_t *data, int len);
    /**
     * @brief finish
     * Finish and reset
     * @param out output array (length of array is mdLen)
     */
    void finish(uint8_t *out);

    /**
     * @brief ~Keccak
     * Delete forUpdate_
     */
    virtual ~Keccak();

    Keccak(const Keccak& other)=delete;
    Keccak(Keccak&& other)=delete;
    Keccak& operator=(const Keccak& other)=delete;
    Keccak& operator=(Keccak&& other)=delete;
};


}//namespace
#endif // FCKECCAK_H
