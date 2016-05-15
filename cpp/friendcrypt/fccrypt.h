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
    friend class CryptWithRng;
private:
    explicit CWKData();
    uint8_t *key_;
    int keyLen_;
    int keyMaxLen_;
public:
    /**
     * @brief kMinLen
     * Minimum reguest length (128 bit)
     */
    static const int kMinLen = 16;

    /**
     * @brief setKey
     * (copy)
     * @param key Key
     * @param len Key length (min: kMinLen)
     * @return true if pass is copied
     */
    bool setKey(const uint8_t *key, int len);

    ~CWKData();
};


/**
 * @brief The CryptWithRng class
 * Encrypt and decrypt with powerful Rng and MixWithRng
 * "Unlimited" key and IV size (>=128)
 * Working level: 224 bit, 256 bit, 384 bit and 512 bit
 * (Not thread safe!)
 */
class CryptWithRng{
    CWKData helper_;
    RngWithKeccak rng_;
    RngWithKeccak ivRng_;
    MixWithRng mixer_;
    uint8_t *iv_;
    int ivLen_;
    int ivMaxLen_;
    void ivCheck(int len);
    bool encode(const uint8_t *dataIn, uint8_t *dataOut, int len);
    bool decode(const uint8_t *dataIn, uint8_t *dataOut, int len);
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
     * @brief CryptWithRng
     * Create Initialization Vector with Rng.reSeed() and time(NULL)
     * @param bitLen Bit size of Keccak: 224, 256, 384, 512 bit
     * @throw invalidArgsException if blockSize is incorrect
     */
    explicit CryptWithRng(int bitLen);

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
    int getIVLen();

    /**
     * @brief setIV
     * Set (copy) Initialization Vector
     * @param iv Initialization Vector
     * @param len Initialization Vector length
     * @return true if success, false if iv is nullptr or len < 16 (128 bit)
     */
    bool setIV(const uint8_t *iv, int len);

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
    bool setKey(const uint8_t *key, int len);

    /**
     * @brief encrypt
     * Encrypt with Rng and MixWithKeccak.mix()
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len data length
     * @return true if success
     */
    bool encrypt(const uint8_t *dataIn, uint8_t *dataOut, int len);

    /**
     * @brief decrypt
     * Decrypt with Rng and MixWithKeccak.reverseMix()
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len data length
     * @return true if success
     */
    bool decrypt(const uint8_t *dataIn, uint8_t *dataOut, int len);

    /**
     * @brief encrypt
     * Encrypt with Rng and MixWithKeccak.crazyMix()
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len data length
     * @return true if success
     */
    bool encryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, int len);

    /**
     * @brief decrypt
     * Decrypt with Rng and MixWithKeccak.reverseCrazyMix()
     * @param dataIn Input data
     * @param dataOut Output data
     * @param len data length
     * @return true if success
     */
    bool decryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, int len);

    /**
     * @brief ~CryptWithRng
     * delete iv_
     */
    virtual ~CryptWithRng();

    //disabled
    CryptWithRng(const CryptWithRng& other)=delete;
    CryptWithRng(CryptWithRng&& other)=delete;
    CryptWithRng& operator=(const CryptWithRng& other)=delete;
    CryptWithRng& operator=(CryptWithRng&& other)=delete;
};


}//namespace
#endif // CRYPT_H
