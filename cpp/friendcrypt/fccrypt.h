#ifndef CRYPT_H
#define CRYPT_H
#include <cstdint>
#include "fcrng.h"
#include "fcmixer.h"

namespace friendcrypt{

/**
 * @brief The CWKData class
 * Helper class
 */
class CWKData{
    friend class CryptWithKeccak;
private:
    explicit CWKData();
    uint8_t *key_;
    long keyLen_;
    long keyMaxLen_;
public:
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

    ~CWKData();
};


/**
 * @brief The CryptWithKeccak class
 * Encrypt and decrypt with powerful Rng and MixWithKeccak
 * "Unlimited" key and IV size (>=128)
 * Working level: 224 bit, 256 bit, 384 bit and 512 bit
 * (Not thread safe!)
 */
class CryptWithKeccak{
    CWKData helper_;
    Rng rng_;
    Rng ivRng_;
    MixWithKeccak mixer_;
    uint8_t *iv_;
    long ivLen_;
    long ivMaxLen_;
    void ivCheck(long len);
    bool encode(const uint8_t *dataIn, uint8_t *dataOut, long len);
    bool decode(const uint8_t *dataIn, uint8_t *dataOut, long len);
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
     * @brief CryptWithKeccak
     * Create Initialization Vector with Rng.reSeed() and time(NULL)
     * @param bitLen Bit size of Keccak: 224, 256, 384, 512 bit
     * @throw invalidArgsException if blockSize is incorrect
     */
    explicit CryptWithKeccak(long bitLen);

    /**
     * @brief createIV
     * Generate random Initialization Vector with Rng
     */
    void createIV();

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
     * @param key Key
     * @param len Key length (min: 16)
     * @return true if pass is copied
     */
    bool setKey(const uint8_t *key, long len);

    /**
     * @brief encrypt
     * Encrypt with Rng and MixWithKeccak.mix()
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len data length
     * @return true if success
     */
    bool encrypt(const uint8_t *dataIn, uint8_t *dataOut, long len);

    /**
     * @brief decrypt
     * Decrypt with Rng and MixWithKeccak.reverseMix()
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len data length
     * @return true if success
     */
    bool decrypt(const uint8_t *dataIn, uint8_t *dataOut, long len);

    /**
     * @brief encrypt
     * Encrypt with Rng and MixWithKeccak.crazyMix()
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len data length
     * @return true if success
     */
    bool encryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, long len);

    /**
     * @brief decrypt
     * Decrypt with Rng and MixWithKeccak.reverseCrazyMix()
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len data length
     * @return true if success
     */
    bool decryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, long len);

    /**
     * @brief ~CryptWithKeccak
     * delete iv_
     */
    virtual ~CryptWithKeccak();

    //disabled
    CryptWithKeccak(const CryptWithKeccak& other)=delete;
    CryptWithKeccak(CryptWithKeccak&& other)=delete;
    CryptWithKeccak& operator=(const CryptWithKeccak& other)=delete;
    CryptWithKeccak& operator=(CryptWithKeccak&& other)=delete;
};


}//namespace
#endif // CRYPT_H
