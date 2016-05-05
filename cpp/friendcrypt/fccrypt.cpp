/*
FriendCrypt
Copyright (C) 2016 OnlineWolf

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

URL: https://github.com/onlinewolf/friendcrypt
*/
#include <string>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <cmath>
#include "fccrypt.h"
#include "fcexception.h"
#include "fcmixer.h"
#include "3rd/keccak.h"

namespace friendcrypt{
//class for help
CWKData::CWKData(long blockLen):kBlockSize(blockLen){
    data_ = nullptr;
    dataLen_ = 0;
    pass_ = new uint8_t[kBlockSize];
    passLen_ = 0;
    salt_ = new uint8_t[kBlockSize];
    saltLen_ = 0;
}

bool CWKData::setData(uint8_t *data, long len){
    if(!data || len<=0)
        return false;

    if(!data_){
        data_ = new uint8_t[len];
        dataMaxLen_ = len;
    }else if(dataMaxLen_ < len){
        delete[] data_;
        data_ = new uint8_t[len];
        dataMaxLen_ = len;
    }

    std::memcpy(data_, data, len);
    dataLen_ = len;
    return true;
}

bool CWKData::setPass(uint8_t *pass, long len){
    if(!pass || len<kMinLen)
        return false;

    if(len>kBlockSize)
        return false;

    std::memcpy(pass_, pass, len);
    passLen_ = len;
    return true;
}

bool CWKData::setSalt(uint8_t *salt, long len){
    if(!salt || len<kMinLen)
        return false;

    if(len>kBlockSize)
        return false;

    std::memcpy(salt_, salt, len);
    saltLen_ = len;
    return true;
}

bool CWKData::getData(uint8_t *data){
    if(!data)
        return false;

    std::memcpy(data, data_, dataLen_);
    return true;
}

long CWKData::getDataLen(){
    return dataLen_;
}

CWKData::~CWKData(){
    if(data_)
        delete data_;
    delete pass_;
    delete salt_;
}


//class
void CryptWithKeccak::creator(){
    if(!DISABLE_SRAND)
        std::srand(std::time(0));

    iv_ = new uint8_t[kBlockSize];
    passAndSaltAndIv_ = new uint8_t[kFullSize];
    hash_ = new uint8_t[kBlockSize];
}

CryptWithKeccak::CryptWithKeccak(): kBlockSize(kMaxHashBlockSize), kFullSize(kMaxHashBlockSize*3), ivCreated_(false){
    creator();
}

CryptWithKeccak::CryptWithKeccak(long blockSize): kBlockSize(blockSize), kFullSize(blockSize*3), ivCreated_(false){
    if(blockSize <= 0 || blockSize > kMaxHashBlockSize || (blockSize % 32) != 0)
        throw invalidArgsException;
    creator();
}

void CryptWithKeccak::createIV(){
    for(long i=0; i<kBlockSize; i++){
        iv_[i] = std::rand() % 256;
    }
    ivCreated_ = true;
}

bool CryptWithKeccak::setIV(uint8_t *iv){
    if(!iv)
        return false;

    std::memcpy(iv_, iv, kBlockSize);
    ivCreated_ = true;
    return true;
}

bool CryptWithKeccak::getIV(uint8_t *iv){
    if(!iv || !ivCreated_)
        return false;

    std::memcpy(iv, iv_, kBlockSize);
    return true;
}

CWKData *CryptWithKeccak::createCWKData(){
    return new CWKData(kBlockSize);
}

void CryptWithKeccak::deleteCWKData(CWKData *data){
    if(data)
        delete data;
}

bool CryptWithKeccak::enCrypt(CWKData* data){
    if(!data || !data->data_ || !data->pass_ || !data->salt_ || data->kBlockSize != kBlockSize || !ivCreated_)
        return false;

    if(data->dataLen_ <= 0 || data->passLen_ <= 0 || data->saltLen_ <= 0)
        return false;

    std::memcpy(passAndSaltAndIv_, data->pass_, data->passLen_);
    std::memcpy(&passAndSaltAndIv_[data->passLen_], data->salt_, data->saltLen_);
    long passAndSaltLen = data->passLen_ + data->saltLen_;
    std::memcpy(&passAndSaltAndIv_[passAndSaltLen], iv_, kBlockSize);
    long psiLen = passAndSaltLen + kBlockSize;//real length

    keccak(passAndSaltAndIv_, psiLen, hash_, kBlockSize);//create hash

    long blockLen = calcBlockSize(hash_[kBlockSize-1], kBlockSize);//first block length
    //keys for mix
    uint8_t *keys = new uint8_t[std::lround(std::ceil((data->dataLen_*1.0) / ((kBlockSize/2)-1.0)))];
    long keyLen = 0;//will be real number of keys

    //encrypt
    for(long i=0; i<data->dataLen_; keyLen++){
        if(i != 0){//no first, create new hash
            std::memcpy(&passAndSaltAndIv_[passAndSaltLen], hash_, kBlockSize);//pass + salt + last hash
            keccak(passAndSaltAndIv_, psiLen, hash_, kBlockSize);//create hash
            blockLen = calcBlockSize(hash_[kBlockSize-1], kBlockSize);//create next block length
        }
        keys[keyLen] = hash_[kBlockSize-1];//put key

        for(long k=0; k<blockLen && i<data->dataLen_; k++, i++){
            data->data_[i] ^= hash_[k];//xor for encrypt
        }
    }

    try{
        MixWithKeccak mixer(data->salt_, data->saltLen_, kBlockSize);
        mixer.mix(data->data_, data->dataLen_, keys, keyLen, kBlockSize);
    }catch(FriendCryptException &e){
        delete[] keys;
        return false;
    }

    delete[] keys;
    return true;
}

bool CryptWithKeccak::deCrypt(CWKData* data){
    if(!data || !data->data_ || !data->pass_ || !data->salt_ || data->kBlockSize != kBlockSize || !ivCreated_)
        return false;

    if(data->dataLen_ <= 0 || data->passLen_ <= 0 || data->saltLen_ <= 0)
        return false;

    std::memcpy(passAndSaltAndIv_, data->pass_, data->passLen_);
    std::memcpy(&passAndSaltAndIv_[data->passLen_], data->salt_, data->saltLen_);
    long passAndSaltLen = data->passLen_ + data->saltLen_;
    std::memcpy(&passAndSaltAndIv_[passAndSaltLen], iv_, kBlockSize);
    long psiLen = passAndSaltLen + kBlockSize;//real length

    keccak(passAndSaltAndIv_, psiLen, hash_, kBlockSize);//create hash

    long blockLen = calcBlockSize(hash_[kBlockSize-1], kBlockSize);//first block length
    //keys for mix
    uint8_t *keys = new uint8_t[std::lround(std::ceil((data->dataLen_*1.0) / ((kBlockSize/2)-1.0)))];
    long keyLen = 0;//will be real number of keys

    //create keys
    for(long i=0; i<data->dataLen_; keyLen++){
        if(i != 0){//no first, create new hash
            std::memcpy(&passAndSaltAndIv_[passAndSaltLen], hash_, kBlockSize);//pass + salt + last hash
            keccak(passAndSaltAndIv_, psiLen, hash_, kBlockSize);//create hash
            blockLen = calcBlockSize(hash_[kBlockSize-1], kBlockSize);//create next block length
        }
        keys[keyLen] = hash_[kBlockSize-1];//put key
        i+=blockLen;
    }
    try{
        MixWithKeccak mixer(data->salt_, data->saltLen_, kBlockSize);
        mixer.reverseMix(data->data_, data->dataLen_, keys, keyLen, kBlockSize);
    }catch(FriendCryptException &e){
        delete[] keys;
        return false;
    }

    //decrypt
    std::memcpy(&passAndSaltAndIv_[passAndSaltLen], iv_, kBlockSize);
    keccak(passAndSaltAndIv_, psiLen, hash_, kBlockSize);//create hash
    blockLen = calcBlockSize(hash_[kBlockSize-1], kBlockSize);//first block length
    for(long i=0; i<data->dataLen_;){
        if(i != 0){//no first, create new hash
            std::memcpy(&passAndSaltAndIv_[passAndSaltLen], hash_, kBlockSize);//pass + salt + last hash
            keccak(passAndSaltAndIv_, psiLen, hash_, kBlockSize);//create hash
            blockLen = calcBlockSize(hash_[kBlockSize-1], kBlockSize);//create next block length
        }

        for(long k=0; k<blockLen && i<data->dataLen_; k++, i++){
            data->data_[i] ^= hash_[k];//xor for decrypt
        }
    }

    delete[] keys;
    return true;
}


CryptWithKeccak::~CryptWithKeccak(){
    delete[] iv_;
    delete[] passAndSaltAndIv_;
    delete[] hash_;
}

//"static" method
}
