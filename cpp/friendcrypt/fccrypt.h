#ifndef CRYPT_H
#define CRYPT_H
#include <cstdint>
namespace friendcrypt{

/**
 * Change to true, If you would like disable auto srand ini.
 * (The createIV() use rand().)
 */
#define DISABLE_SRAND false

/**
 * @brief The CWKData class
 * Object creator: CryptWithKeccak
 */
class CWKData{
    friend class CryptWithKeccak;
private:
    explicit CWKData(long blockLen);
    uint8_t *data_;
    long dataLen_;
    long dataMaxLen_;
    uint8_t *pass_;
    long passLen_;
    uint8_t *salt_;
    long saltLen_;
public:
    /**
     * @brief kBlockSize
     * Actual block size
     */
    const long kBlockSize;

    /**
     * @brief kMinLen
     * Minimum reguest length
     */
    const int kMinLen = 16;

    /**
     * @brief setData
     * Set crypted data or plaintext (copy)
     * (This will rewrite in inside buffer if you use encode/decode)
     * @param data crypted data or plaintext
     * @param len length
     * @return true if data is copied
     */
    bool setData(uint8_t *data, long len);

    /**
     * @brief setPass
     * (copy)
     * @param pass password
     * @param len length (no more than Block Size, min: kMinLen)
     * @return true if pass is copied
     */
    bool setPass(uint8_t *pass, long len);

    /**
     * @brief setSalt
     * (copy)
     * @param salt
     * @param len length (no more than Block Size, min: kMinLen)
     * @return true if salt is copied
     */
    bool setSalt(uint8_t *salt, long len);

    /**
     * @brief getData
     * (copy, crypted data length and plaintext length is equals)
     * @param data
     * @return true if data is copied
     */
    bool getData(uint8_t* data);

    /**
     * @brief getDataLen
     * @return data length
     */
    long getDataLen();
    virtual ~CWKData();
};

class CryptWithKeccak{
    const int kFullSize;
    bool ivCreated_;
    uint8_t *iv_;
    uint8_t *passAndSaltAndIv_;
    uint8_t *hash_;
    void creator();
public:
    /**
     * @brief kBlockSize
     * Actual block size
     */
    const int kBlockSize;

    const int kMaxHashBlockSize = 64;

    /**
     * @brief CryptWithKeccak
     * Create new object with kMaxHashBlockSize
     */
    CryptWithKeccak();

    /**
     * @brief CryptWithKeccak
     * @param blockSize 32 or 64 byte
     * @throw invalidArgsException if blockSize is incorrect
     */
    explicit CryptWithKeccak(long blockSize);

    /**
     * @brief createIV
     * Generate random IV with rand() (this class use std::srand() in constructors)
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
     * @return true if success, false if fail
     */
    bool getIV(uint8_t *iv);

    /**
     * @brief createCWKData
     * If you want delete this object use: deleteCWKData() or delete
     * @return CWKData object
     */
    CWKData *createCWKData();

    /**
     * @brief deleteCWKData
     * Delete CWKData object
     * @param data CWKData object
     */
    void deleteCWKData(CWKData *data);

    bool enCrypt(CWKData* data);

    bool deCrypt(CWKData* data);

    virtual ~CryptWithKeccak();

    CryptWithKeccak(const CryptWithKeccak& other)=delete;
    CryptWithKeccak(CryptWithKeccak&& other)=delete;
    CryptWithKeccak& operator=(const CryptWithKeccak& other)=delete;
    CryptWithKeccak& operator=(CryptWithKeccak&& other)=delete;
};

}
#endif // CRYPT_H
