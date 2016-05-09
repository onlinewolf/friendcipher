#ifndef FCKECCAK_H
#define FCKECCAK_H
#include <cstdint>

namespace friendcrypt{

/**
 * @brief The Keccak class
 * 3rd Keccak C++ implementation
 */
class Keccak{
    const int kKeccakRounds = 24;
    uint64_t forDigest_[25];
    uint8_t* forUpdate_;
    int updatePos_;
    int rsiz_;
    int rsizw_;
    int mdLen_;
    void reset();
public:
    /**
     * @brief Keccak
     * Message digest len (byte)
     * @param mdLen
     */
    explicit Keccak(int mdLen);
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
