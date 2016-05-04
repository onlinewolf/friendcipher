#ifndef CRYPT_H
#define CRYPT_H
#include <cstdint>
namespace friendcrypt{

class CryptWithKeccak{
    const int kMaxBlockSize;
    const int kFullSize;
    uint8_t *iv_;
    uint8_t *saltAndPassAndIv_;
    void creator(long blockSize);
    void useIV();
public:
    /**
     * @brief CryptWithKeccak
     * Create new object with 64 byte blockSize
     */
    CryptWithKeccak();

    /**
     * @brief CryptWithKeccak
     * @param blockSize 32 or 64 byte
     */
    CryptWithKeccak(long blockSize);

    /**
     * @brief createIV
     * Generate random IV
     */
    void createIV();

    /**
     * @brief setIV
     * Set (copy) IV for crypt
     * @param iv (blockSize len)
     * @return true if success, false if iv is NULL or nullptr
     */
    bool setIV(uint8_t *iv);

    /**
     * @brief getIV
     * Get copy of IV
     * @param iv (blockSize len)
     */
    void getIV(uint8_t *iv);
    ~CryptWithKeccak();
};

}
#endif // CRYPT_H
