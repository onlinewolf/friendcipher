#include <iostream>
#include <iomanip>
#include "fcmixer.h"
#include "fcexception.h"
#include "fccipher.h"
#include "fchash.h"
#include "fcrng.h"
#include "fctspeed.h"

void convert(uint64_t x){
    if(x > 1024*1024*1024)
        std::cout << x/(1024*1024*1024) << " GBps";
    else if(x > 1024*1024)
        std::cout << x/(1024*1024) << " MBps";
    else if(x > 1024)
        std::cout << x/1024 << " kBps";
    else
        std::cout << x << " Bps";
}

/*
 * Fast test!
 */
int main(int argc, char *argv[]){
    const int kMdBitLen = 512;
    const int kMdLen = kMdBitLen/8;

    friendcipher::RngWithHash rng(kMdBitLen);
    time_t ti = time(NULL);
    rng.init((uint8_t*)&ti, sizeof(ti), nullptr, 0);


    //for test
    //data
    const int kDataLen = 32*1024;
    uint8_t *data = new uint8_t[kDataLen];
    uint8_t *dataOut = new uint8_t[kDataLen];
    uint8_t *dataOut2 = new uint8_t[kDataLen];
    for(int i=0; i<kDataLen; i++){
        data[i] = rng.random8bit();
    }

    /*//key
    const int kKeyLen = 48;
    uint8_t *key = new uint8_t[kKeyLen];
    for(int i=0; i<kKeyLen; i++){
        key[i] = rng.random8bit();
    }

    //iv
    const int kIvLen = 48;
    uint8_t *iv = new uint8_t[kIvLen];
    for(int i=0; i<kIvLen; i++){
        iv[i] = rng.random8bit();
    }

    //for crypt
    //data
    const int kDataLen = 80;
    uint8_t *data = new uint8_t[kDataLen];
    for(int i=0; i<kDataLen; i++){
        data[i] = i;
    }

    uint8_t *dataOut = new uint8_t[kDataLen];
    uint8_t *dataOut2 = new uint8_t[kDataLen];*/

    //key
    const int kKeyLen = 16;
    uint8_t *key = new uint8_t[kKeyLen];
    for(int i=0; i<kKeyLen; i++){
        key[i] = i;
    }

    //iv
    const int kIvLen = 16;
    uint8_t *iv = new uint8_t[kIvLen];
    for(int i=0; i<kIvLen; i++){
        iv[i] = i;
    }


    ///Keccak speed test
    std::cout << "(Keccak) Data length: " << kDataLen << std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::keccakSpeed(224, data, kDataLen, dataOut)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::keccakSpeed(256, data, kDataLen, dataOut)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::keccakSpeed(384, data, kDataLen, dataOut)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::keccakSpeed(512, data, kDataLen, dataOut)); std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

    //Rng speed test
    std::cout << "(Rng) Data length: " << kDataLen << std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::rngSpeed(224, key, kKeyLen, iv, kIvLen, dataOut, kDataLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::rngSpeed(256, key, kKeyLen, iv, kIvLen, dataOut, kDataLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::rngSpeed(384, key, kKeyLen, iv, kIvLen, dataOut, kDataLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::rngSpeed(512, key, kKeyLen, iv, kIvLen, dataOut, kDataLen)); std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

/*
    //mix speed test
    std::cout << "(mix) Data length: " << kDataLen << ", Key length: " << kKeyLen*8 << " bit, IV length: " << kIvLen*8 << " bit"<< std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::mixSpeed(true, false, 224, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::mixSpeed(true, false, 256, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::mixSpeed(true, false, 384, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::mixSpeed(true, false, 512, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "(reverseMix) Data length: " << kDataLen << ", Key length: " << kKeyLen*8 << " bit, IV length: " << kIvLen*8 << " bit"<< std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::mixSpeed(false, false, 224, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::mixSpeed(false, false, 256, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::mixSpeed(false, false, 384, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::mixSpeed(false, false, 512, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << std::endl;

    /*std::cout << "(crazyMix) Data length: " << kDataLen << ", Key length: " << kKeyLen*8 << " bit, IV length: " << kIvLen*8 << " bit"<< std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::mixSpeed(true, true, 224, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::mixSpeed(true, true, 256, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::mixSpeed(true, true, 384, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::mixSpeed(true, true, 512, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "(reverseCrazyMix) Data length: " << kDataLen << ", Key length: " << kKeyLen*8 << " bit, IV length: " << kIvLen*8 << " bit"<< std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::mixSpeed(false, true, 224, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::mixSpeed(false, true, 256, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::mixSpeed(false, true, 384, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::mixSpeed(false, true, 512, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;*/


    //crypt speed test
    std::cout << "(encrypt) Data length: " << kDataLen << " byte, Key length: " << kKeyLen*8 << " bit, IV length: " << kIvLen*8 << " bit"<< std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::cipherSpeed(true, false, 224, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::cipherSpeed(true, false, 256, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::cipherSpeed(true, false, 384, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::cipherSpeed(true, false, 512, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "(encrypt) Data length: " << kDataLen << ", Key length: " << kKeyLen*8 << " bit" << std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::cipherSpeed(true, false, 224, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 224 bit)" << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::cipherSpeed(true, false, 256, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 256 bit)" << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::cipherSpeed(true, false, 384, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 384 bit)" << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::cipherSpeed(true, false, 512, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 512 bit)" << std::endl;
    std::cout << std::endl;

    std::cout << "(decrypt) Data length: " << kDataLen << " byte, Key length: " << kKeyLen*8 << " bit, IV length: " << kIvLen*8 << " bit"<< std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::cipherSpeed(false, false, 224, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::cipherSpeed(false, false, 256, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::cipherSpeed(false, false, 384, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::cipherSpeed(false, false, 512, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "(decrypt) Data length: " << kDataLen << ", Key length: " << kKeyLen*8 << " bit" << std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::cipherSpeed(false, false, 224, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 224 bit)" << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::cipherSpeed(false, false, 256, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 256 bit)" << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::cipherSpeed(false, false, 384, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 384 bit)" << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::cipherSpeed(false, false, 512, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 512 bit)" << std::endl;
    std::cout << std::endl;
    std::cout << std::endl;

/*
    std::cout << "(crazyEncrypt) Data length: " << kDataLen << " byte, Key length: " << kKeyLen*8 << " bit, IV length: " << kIvLen*8 << " bit"<< std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::cipherSpeed(true, true, 224, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::cipherSpeed(true, true, 256, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::cipherSpeed(true, true, 384, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::cipherSpeed(true, true, 512, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "(crazyEncrypt) Data length: " << kDataLen << ", Key length: " << kKeyLen*8 << " bit" << std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::cipherSpeed(true, true, 224, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 224 bit)" << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::cipherSpeed(true, true, 256, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 256 bit)" << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::cipherSpeed(true, true, 384, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 384 bit)" << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::cipherSpeed(true, true, 512, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 512 bit)" << std::endl;
    std::cout << std::endl;

    std::cout << "(crazyDecrypt) Data length: " << kDataLen << " byte, Key length: " << kKeyLen*8 << " bit, IV length: " << kIvLen*8 << " bit"<< std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::cipherSpeed(false, true, 224, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::cipherSpeed(false, true, 256, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::cipherSpeed(false, true, 384, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::cipherSpeed(false, true, 512, data, dataOut, kDataLen, key, kKeyLen, iv, kIvLen)); std::cout << std::endl;
    std::cout << std::endl;

    std::cout << "(crazyDecrypt) Data length: " << kDataLen << ", Key length: " << kKeyLen*8 << " bit" << std::endl;
    std::cout << "224 bit: "; convert(friendcipher::test::cipherSpeed(false, true, 224, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 224 bit)" << std::endl;
    std::cout << "256 bit: "; convert(friendcipher::test::cipherSpeed(false, true, 256, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 256 bit)" << std::endl;
    std::cout << "384 bit: "; convert(friendcipher::test::cipherSpeed(false, true, 384, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 384 bit)" << std::endl;
    std::cout << "512 bit: "; convert(friendcipher::test::cipherSpeed(false, true, 512, data, dataOut, kDataLen, key, kKeyLen, nullptr, 0)); std::cout << ", (IV: 512 bit)" << std::endl;
    std::cout << std::endl;*/

    /*//other minimal test
    friendcipher::MixWithRng mixer(kMdBitLen);
    mixer.init(key, kKeyLen, iv, kIvLen);
    mixer.mix(data, dataOut, kDataLen, 0);

    for (int i=0; i<kDataLen; i++) {
        std::cout << std::dec << std::uppercase << static_cast<int>(dataOut[i]) << ", ";
    }
    std::cout << std::endl;
    std::cout << std::endl;

    mixer.reverseMix(dataOut, dataOut2, kDataLen, 0);

    for (int i=0; i<kDataLen; i++) {
        std::cout << std::dec << std::uppercase << static_cast<int>(dataOut2[i]) << ", ";
    }
    std::cout << std::endl;
    std::cout << std::endl;*/


    /*//normal crypt
    friendcipher::CryptWithRng enCrypt(kMdBitLen);
    enCrypt.setKey(key, kKeyLen);
    friendcipher::CryptWithRng deCrypt(kMdBitLen);//for test
    deCrypt.setKey(key, kKeyLen);

    enCrypt.createIV();
    uint8_t iv2[kMdLen];

    for(int a=0; a<10; a++){
        enCrypt.createIV();
        enCrypt.getIV(iv2);
        deCrypt.setIV(iv2, enCrypt.getIVLen());
        std::cout << "iv: ";
        for (int i=0; i<kMdLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(iv2[i]);
        }
        std::cout << std::endl;

        //plaintext
        std::cout << "data:    ";
        for (int i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(data[i]);
        }
        std::cout << std::endl;




        //encrypt
        enCrypt.encrypt(data, dataOut, kDataLen);
        std::cout << "encrypt: ";
        for (int i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut[i]);
        }
        std::cout << std::endl;

        //decrypt
        deCrypt.decrypt(dataOut, dataOut2, kDataLen);
        std::cout << "decrypt: ";
        for (int i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut2[i]);
        }
        std::cout << std::endl;
        std::cout << std::endl;
    }*/

    /*//try crazy crypt
    friendcipher::CryptWithRng enCrypt(kMdBitLen);
    enCrypt.setKey(key, kKeyLen);
    friendcipher::CryptWithRng deCrypt(kMdBitLen);//for test
    deCrypt.setKey(key, kKeyLen);

    enCrypt.createIV();
    uint8_t iv2[kMdLen];

    for(int a=0; a<10; a++){
        enCrypt.createIV();
        enCrypt.getIV(iv2);
        deCrypt.setIV(iv2, enCrypt.getIVLen());
        std::cout << "iv: ";
        for (int i=0; i<kMdLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(iv2[i]);
        }
        std::cout << std::endl;

        //plaintext
        std::cout << "data:    ";
        for (int i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(data[i]);
        }
        std::cout << std::endl;




        //encrypt
        enCrypt.encryptCrazy(data, dataOut, kDataLen);
        std::cout << "encrypt: ";
        for (int i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut[i]);
        }
        std::cout << std::endl;

        //decrypt
        deCrypt.decryptCrazy(dataOut, dataOut2, kDataLen);
        std::cout << "decrypt: ";
        for (int i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(dataOut2[i]);
        }
        std::cout << std::endl;
        std::cout << std::endl;
    }*/

    /*//try crypt
    friendcipher::CryptWithRng enCrypt(kMdBitLen);
    enCrypt.setKey(key, kKeyLen);
    enCrypt.setIV(iv, kIvLen);
    friendcipher::CryptWithRng deCrypt(kMdBitLen);//for test
    deCrypt.setKey(key, kKeyLen);

    //IV
    enCrypt.getIV(iv);
    deCrypt.setIV(iv, enCrypt.getIVLen());
    std::cout << "iv: ";
    for (int i=0; i<kIvLen; i++) {
        std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(iv[i]);
    }
    std::cout << std::endl;
    std::cout << std::endl;

    //plaintext
    std::cout << "data:    ";
    for (int i=0; i<kDataLen; i++) {
        std::cout << std::dec << static_cast<int>(data[i]) << ", ";
    }
    std::cout << std::endl;
    std::cout << std::endl;

    //encrypt
    enCrypt.encrypt(data, dataOut, kDataLen);
    std::cout << "encrypt: ";
    for (int i=0; i<kDataLen; i++) {
        std::cout << std::dec << static_cast<int>(dataOut[i]) << ", ";
    }
    std::cout << std::endl;
    std::cout << std::endl;

    //decrypt
    deCrypt.decrypt(dataOut, dataOut2, kDataLen);
    std::cout << "decrypt: ";
    for (int i=0; i<kDataLen; i++) {
        std::cout << std::dec << static_cast<int>(dataOut2[i]) << ", ";
    }
    std::cout << std::endl;
    std::cout << std::endl;*/

    uint8_t data1[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40};
    uint8_t data2[]{41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80};

    uint8_t mDigest[kMdLen];
    //fc
    friendcipher::Hash hash(kMdBitLen);
    hash.update(data1, 40);
    hash.update(data2, 40);
    hash.finish(mDigest);
    //show
    for(int i=0; i<kMdLen; i++){
        std::cout << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << static_cast<int>(mDigest[i]);
    }
    std::cout << std::endl;


   /* rng.init((uint8_t*)&ti, sizeof(ti), nullptr, 0);
    std::cout << std::hex << "r8:   " << static_cast<int>(rng.random8bit()) << std::endl;
    std::cout << std::hex << "1r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "2r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "3r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "4r32: " << static_cast<int>(rng.random32bit()) << std::endl;

    rng.init((uint8_t*)&ti, sizeof(ti), data1, 4);
    std::cout << std::hex << "r8:   " << static_cast<int>(rng.random8bit()) << std::endl;
    std::cout << std::hex << "1r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "2r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "3r32: " << static_cast<int>(rng.random32bit()) << std::endl;
    std::cout << std::hex << "4r32: " << static_cast<int>(rng.random32bit()) << std::endl;

    std::cout << std::endl;

    rng.init(data1, 40, nullptr, 0);
    std::cout << std::dec << "r8:   " << static_cast<int>(rng.random8bit()) << std::endl;
    std::cout << std::dec << "1r32: " << rng.random32bit() << std::endl;

    rng.init(data1, 40, data2, 40);
    std::cout << std::dec << "r8:   " << static_cast<int>(rng.random8bit()) << std::endl;
    std::cout << std::dec << "1r32: " << rng.random32bit() << std::endl;

    rng.reSeed(data1, 40);
    std::cout << std::dec << "r8:   " << static_cast<int>(rng.random8bit()) << std::endl;
    std::cout << std::dec << "1r32: " << rng.random32bit() << std::endl;*/

    delete[] data;
    delete[] key;
    delete[] iv;
    delete[] dataOut;
    delete[] dataOut2;
    return 0;
}
