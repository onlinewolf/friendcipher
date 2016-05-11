#ifndef CRYPT_H
#define CRYPT_H
#include <cstdint>
#include "fcrng.h"

namespace friendcrypt{

/**
 * @brief The CWKData class
 * Helper class
 */
class CWKData{
    friend class CryptWithKeccak;
private:
    explicit CWKData(long blockLen);
    uint8_t *key_;
    long keyLen_;
    long keyMaxLen_;
    uint8_t *salt_;
    long saltLen_;
    long saltMaxLen_;
public:
    /**
     * @brief kBlockSize
     * Actual block size
     */
    const long kBlockSize;

    /**
     * @brief kMinLen
     * Minimum reguest length (128 bit)
     */
    static const long kMinLen = 16;

    /**
     * @brief setKey
     * (copy)
     * @param key Key
     * @param len Key length (min: kMinLen)
     * @return true if pass is copied
     */
    bool setKey(const uint8_t *key, long len);

    /**
     * @brief setSalt
     * (copy)
     * @param salt Salt
     * @param len Salt length (min: kMinLen)
     * @return true if salt is copied
     */
    bool setSalt(const uint8_t *salt, long len);

    ~CWKData();
};


/**
 * @brief The CryptWithKeccak class
 * Encrypt and decrypt
 */
class CryptWithKeccak{
    CWKData helper_;
    Rng *rng_;
    uint8_t *iv_;
    long ivLen_;
    long ivMaxLen_;
    void ivCheck(long len);
    bool encode(const uint8_t *dataIn, uint8_t *dataOut, long len);
    bool decode(const uint8_t *dataIn, uint8_t *dataOut, long len);
public:
    /**
     * @brief CryptWithKeccak
     * Initalisation
     * @param blockSize Bit size of block 224, 256, 384, 512 bit
     * @throw invalidArgsException if blockSize is incorrect
     */
    explicit CryptWithKeccak(long blockBitSize);

    /**
     * @brief createIV
     * Generate random Initialization Vector with Rng() and time(NULL)
     * @param salt Salt
     * @param len Length
     * @return true if success, false if salt is nullptr or len == 0
     */
    bool createIV(const uint8_t *salt, long len);

    /**
     * @brief getIVLen
     * Get Initialization Vector length
     * @return Initialization Vector length or 0 if not have IV
     */
    long getIVLen();

    /**
     * @brief setIV
     * Set (copy) Initialization Vector
     * @param iv Initialization Vector
     * @param len Initialization Vector length
     * @return true if success, false if iv is nullptr or len < 16 (128 bit)
     */
    bool setIV(const uint8_t *iv, long len);

    /**
     * @brief getIV
     * Get copy of Initialization Vector
     * @param iv Initialization Vector
     * @return true if success, false if fail
     */
    bool getIV(uint8_t *iv);

    /**
     * @brief setKey
     * (copy)
     * @param pass Key
     * @param len Key length (min: 16)
     * @return true if pass is copied
     */
    bool setKey(const uint8_t *key, long len);

    /**
     * @brief setSalt
     * (copy)
     * @param salt Salt
     * @param len Salt length (min: 16)
     * @return true if salt is copied
     */
    bool setSalt(const uint8_t *salt, long len);

    /**
     * @brief encrypt
     * Encrypt with Keccak and mix()
     * @return true if success
     */
    bool encrypt(const uint8_t *dataIn, uint8_t *dataOut, long len);

    /**
     * @brief decrypt
     * Decrypt with Keccak and reverseMix()
     * @return true if success
     */
    bool decrypt(const uint8_t *dataIn, uint8_t *dataOut, long len);

    /**
     * @brief encrypt
     * Encrypt with Keccak and crazyMix()
     * @return true if success
     */
    bool encryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, long len);

    /**
     * @brief decrypt
     * Decrypt with Keccak and reverseCrazyMix()
     * @return true if success
     */
    bool decryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, long len);

    virtual ~CryptWithKeccak();

    //disabled
    CryptWithKeccak(const CryptWithKeccak& other)=delete;
    CryptWithKeccak(CryptWithKeccak&& other)=delete;
    CryptWithKeccak& operator=(const CryptWithKeccak& other)=delete;
    CryptWithKeccak& operator=(CryptWithKeccak&& other)=delete;
};


}//namespace
#endif // CRYPT_H
