#include <iostream>
#include <iomanip>
#include <fcmixer.h>
#include "fcexception.h"
#include "fccrypt.h"

int main(int argc, char *argv[]){
    const long kBlockLen = 32;

    const long kDataLen = 64;
    uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                              21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                              41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
                              61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80};
    const long kPassLen = 24;
    uint8_t pass[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};
    const long kSaltLen = 16;
    uint8_t salt[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    friendcrypt::CryptWithKeccak enCrypt(kBlockLen);
    friendcrypt::CryptWithKeccak deCrypt(kBlockLen);//for test

    friendcrypt::CWKData* forEnCrypt = enCrypt.createCWKData();
    friendcrypt::CWKData* forDeCrypt = enCrypt.createCWKData();
    forEnCrypt->setPass(pass, kPassLen);
    forEnCrypt->setSalt(salt, kSaltLen);
    //test
    forDeCrypt->setPass(pass, kPassLen);
    forDeCrypt->setSalt(salt, kSaltLen);

    uint8_t iv[kBlockLen];

    for(int a=0; a<10; a++){
        enCrypt.createIV();
        enCrypt.getIV(iv);
        std::cout << "iv: ";
        for (long i=0; i<kBlockLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(iv[i]);
        }
        std::cout << std::endl;

        //plaintext
        std::cout << "data:    ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(data[i]);
        }
        std::cout << std::endl;




        //encrypt
        forEnCrypt->setData(data, kDataLen);
        enCrypt.enCrypt(forEnCrypt);
        forEnCrypt->getData(data);
        std::cout << "encrypt: ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(data[i]);
        }
        std::cout << std::endl;

        //decrypt
        deCrypt.setIV(iv);
        forDeCrypt->setData(data, kDataLen);
        deCrypt.deCrypt(forDeCrypt);
        forDeCrypt->getData(data);
        std::cout << "decrypt: ";
        for (long i=0; i<kDataLen; i++) {
            std::cout << std::hex << std::setw(2) << std::uppercase << static_cast<int>(data[i]);
        }
        std::cout << std::endl;
        std::cout << std::endl;
    }
    //correct end
    delete forEnCrypt;
    delete forDeCrypt;
    return 0;
}
