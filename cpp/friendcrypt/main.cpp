#include <iostream>
#include <iomanip>
#include "fcmixer.h"
#include "fcexception.h"
#include "fccrypt.h"
#include "fckeccak.h"
#include "fcrng.h"


/*
 * Fast test!
 */
int main(int argc, char *argv[]){
    const long kMdBitLen = 512;
    const long kMdLen = kMdBitLen/8;


    const long kDataLen = 16;
    uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                              21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                              41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                              61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80};
    uint8_t dataOut[kDataLen];
    uint8_t dataOut2[kDataLen];
    const long kKeyLen = 16;
    uint8_t key[kKeyLen] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const long kIvLen = 16;
    uint8_t iv[kIvLen] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /*friendcrypt::MixWithKeccak mixer(kMdBitLen);
    mixer.init(key, kKeyLen, iv, kIvLen);
    mixer.crazyMix(data, dataOut, kDataLen);

    for (long i=0; i<kDataLen; i++) {
        std::cout << std::dec << std::uppercase << static_cast<int>(dataOut[i]) << ", ";
    }
    std::cout << std::endl;
    std::cout << std::endl;

    mixer.reverseCrazyMix(dataOut, dataOut2, kDataLen);

    for (long i=0; i<kDataLen; i++) {
        std::cout << std::dec << std::uppercase << static_cast<int>(dataOut2[i]) << ", ";
    }
    std::cout << std::endl;*/


    /*//normal crypt
    friendcrypt::CryptWithKeccak enCrypt(kMdBitLen);
    enCrypt.setKey(key, kKeyLen);
    friendcrypt::CryptWithKeccak deCrypt(kMdBitLen);//for test
    deCrypt.setKey(key, kKeyLen);

    enCrypt.createIV();
    uint8_t iv2[kMdLen];

    for(int a=0; a<10; a++){
        enCrypt.createIV();
        enCrypt.getIV(iv2);
        deCrypt.setIV(iv2, enCrypt.getIVLen());
        std::cout << "iv: ";
        for (long i=0; i<kMdLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(iv2[i]);
        }
        std::cout << std::endl;

        //plaintext
        std::cout << "data:    ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(data[i]);
        }
        std::cout << std::endl;




        //encrypt
        enCrypt.encrypt(data, dataOut, kDataLen);
        std::cout << "encrypt: ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut[i]);
        }
        std::cout << std::endl;

        //decrypt
        deCrypt.decrypt(dataOut, dataOut2, kDataLen);
        std::cout << "decrypt: ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut2[i]);
        }
        std::cout << std::endl;
        std::cout << std::endl;
    }*/

    //try crazy crypt
    friendcrypt::CryptWithKeccak enCrypt(kMdBitLen);
    enCrypt.setKey(key, kKeyLen);
    friendcrypt::CryptWithKeccak deCrypt(kMdBitLen);//for test
    deCrypt.setKey(key, kKeyLen);

    enCrypt.createIV();
    uint8_t iv2[kMdLen];

    for(int a=0; a<10; a++){
        enCrypt.createIV();
        enCrypt.getIV(iv2);
        deCrypt.setIV(iv2, enCrypt.getIVLen());
        std::cout << "iv: ";
        for (long i=0; i<kMdLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(iv2[i]);
        }
        std::cout << std::endl;

        //plaintext
        std::cout << "data:    ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(data[i]);
        }
        std::cout << std::endl;




        //encrypt
        enCrypt.encryptCrazy(data, dataOut, kDataLen);
        std::cout << "encrypt: ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut[i]);
        }
        std::cout << std::endl;

        //decrypt
        deCrypt.decryptCrazy(dataOut, dataOut2, kDataLen);
        std::cout << "decrypt: ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut2[i]);
        }
        std::cout << std::endl;
        std::cout << std::endl;
    }

    /*//try crazy crypt
    friendcrypt::CryptWithKeccak enCrypt(kMdBitLen);
    enCrypt.setKey(key, kKeyLen);
    enCrypt.setIV(iv, kIvLen);
    friendcrypt::CryptWithKeccak deCrypt(kMdBitLen);//for test
    deCrypt.setKey(key, kKeyLen);

    //IV
    enCrypt.getIV(iv);
    deCrypt.setIV(iv, enCrypt.getIVLen());
    std::cout << "iv: ";
    for (long i=0; i<kIvLen; i++) {
        std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(iv[i]);
    }
    std::cout << std::endl;
    std::cout << std::endl;

    //plaintext
    std::cout << "data:    ";
    for (long i=0; i<kDataLen; i++) {
        std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(data[i]);
    }
    std::cout << std::endl;
    std::cout << std::endl;

    //encrypt
    enCrypt.encryptCrazy(data, dataOut, kDataLen);
    std::cout << "encrypt: ";
    for (long i=0; i<kDataLen; i++) {
        std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut[i]);
    }
    std::cout << std::endl;
    std::cout << std::endl;

    //decrypt
    deCrypt.decryptCrazy(dataOut, dataOut2, kDataLen);
    std::cout << "decrypt: ";
    for (long i=0; i<kDataLen; i++) {
        std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut2[i]);
    }
    std::cout << std::endl;
    std::cout << std::endl;*/

    uint8_t data1[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40};
    uint8_t data2[]{41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80};

    uint8_t mDigest[kMdLen];
    //fc
    friendcrypt::Keccak hash(kMdBitLen);
    hash.update(data1, 40);
    hash.update(data2, 40);
    hash.finish(mDigest);
    //show
    for (long i=0; i<kMdLen; i++) {
        std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(mDigest[i]);
    }
    std::cout << std::endl;

    /*uint32_t ti = static_cast<uint32_t>(time(NULL));
    friendcrypt::Rng rng(kMdBitLen);
    uint8_t data1[]{1, 2, 3, 5};

    rng.init((uint8_t*)&ti, 4, nullptr, 0);
    std::cout << std::hex << "r8:   " << static_cast<int>(rng.random8bit()) << std::endl;
    std::cout << std::hex << "1r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "2r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "3r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "4r32: " << static_cast<int>(rng.random32bit()) << std::endl;

    rng.init((uint8_t*)&ti, 4, data1, 4);
    std::cout << std::hex << "r8:   " << static_cast<int>(rng.random8bit()) << std::endl;
    std::cout << std::hex << "1r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "2r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "3r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "4r32: " << static_cast<int>(rng.random32bit()) << std::endl;

    rng.init(data1, 4, nullptr, 0);
    std::cout << std::hex << "r8:   " << static_cast<int>(rng.random8bit()) << std::endl;
    std::cout << std::hex << "1r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "2r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "3r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "4r32: " << static_cast<int>(rng.random32bit()) << std::endl;*/

    return 0;
}
