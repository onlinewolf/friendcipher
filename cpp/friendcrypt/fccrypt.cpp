/*
friendcrypt::CryptWithKeccak
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
#include <cmath>
#include <ctime>
#include "fccrypt.h"
#include "fcexception.h"
#include "fcmixer.h"
#include "fckeccak.h"

namespace friendcrypt{

//class
CryptWithKeccak::CryptWithKeccak(long blockBitSize): helper_(blockBitSize/8){
    if(blockBitSize != 224 && blockBitSize != 256 && blockBitSize != 384 && blockBitSize != 512)
        throw invalidArgsException;

    iv_ = nullptr;
    uint32_t temp = static_cast<uint32_t>(time(NULL));
    rng_ = new Rng((uint8_t*)&temp, 4, nullptr, 0);
}

void CryptWithKeccak::ivCheck(long len){
    if(len <= 0)
        return;

    if(!iv_){
        iv_ = new uint8_t[len];
        ivMaxLen_ = len;
    }else if(ivMaxLen_ < len){
        delete[] iv_;
        iv_ = new uint8_t[len];
        ivMaxLen_ = len;
    }
}

bool CryptWithKeccak::createIV(const uint8_t *salt, long len){
    if(!salt || len <= 0)
        return false;

    ivCheck(helper_.kBlockSize);
    ivLen_ = helper_.kBlockSize;

    rng_->reSeed(salt, len);

    for(long i=0; i<helper_.kBlockSize; i++)
        iv_[i] = rng_->random8bit();

    return true;
}

long CryptWithKeccak::getIVLen(){
    if(!iv_)
        return 0;

    return ivLen_;
}

bool CryptWithKeccak::setIV(const uint8_t *iv, long len){
    if(!iv || len < helper_.kMinLen)
        return false;

    ivCheck(len);
    ivLen_ = len;

    std::memcpy(iv_, iv, len);
    return true;
}

bool CryptWithKeccak::getIV(uint8_t *iv){
    if(!iv)
        return false;

    std::memcpy(iv, iv_, ivLen_);
    return true;
}

bool CryptWithKeccak::setKey(const uint8_t *key, long len){
    return helper_.setKey(key, len);
}

bool CryptWithKeccak::setSalt(const uint8_t *salt, long len){
    return helper_.setSalt(salt, len);
}


bool CryptWithKeccak::encode(const uint8_t *dataIn, uint8_t *dataOut, long len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_ || !helper_.salt_)
        return false;

    try{
        Rng rng(helper_.key_, helper_.keyLen_, helper_.salt_, helper_.saltLen_);
        rng.reSeed(iv_, ivLen_);
        for(long i=0; i<len; i++)
            dataOut[i] = dataIn[i] ^ rng.random8bit();
    }catch(FriendCryptException &e){
        return false;
    }

    return true;
}

bool CryptWithKeccak::decode(const uint8_t *dataIn, uint8_t *dataOut, long len){
    return encode(dataIn, dataOut, len);
}


bool CryptWithKeccak::encrypt(const uint8_t *dataIn, uint8_t *dataOut, long len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_ || !helper_.salt_)
        return false;

    if(!encode(dataIn, dataOut, len))
        return false;

    try{
        MixWithKeccak mixer(helper_.key_, helper_.keyLen_, iv_, ivLen_, helper_.salt_, helper_.saltLen_);
        if(!mixer.mix(dataOut, dataOut, len, 0))
            return false;
    }catch(FriendCryptException &e){
        return false;
    }

    return true;
}


bool CryptWithKeccak::decrypt(const uint8_t *dataIn, uint8_t *dataOut, long len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_ || !helper_.salt_)
        return false;

    try{
        MixWithKeccak mixer(helper_.key_, helper_.keyLen_, iv_, ivLen_, helper_.salt_, helper_.saltLen_);
        if(!mixer.reverseMix(dataIn, dataOut, len, 0))
            return false;
    }catch(FriendCryptException &e){
        return false;
    }

    if(!decode(dataOut, dataOut, len))
        return false;

    return true;
}


bool CryptWithKeccak::encryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, long len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_ || !helper_.salt_)
        return false;

    if(!encode(dataIn, dataOut, len))
        return false;

    try{
        MixWithKeccak mixer(helper_.key_, helper_.keyLen_, iv_, ivLen_, helper_.salt_, helper_.saltLen_);
        if(!mixer.crazyMix(dataOut, dataOut, len))
            return false;
    }catch(FriendCryptException &e){
        return false;
    }


    return true;
}

bool CryptWithKeccak::decryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, long len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_ || !helper_.salt_)
        return false;

    try{
        MixWithKeccak mixer(helper_.key_, helper_.keyLen_, iv_, ivLen_, helper_.salt_, helper_.saltLen_);
        if(!mixer.reverseCrazyMix(dataIn, dataOut, len))
            return false;
    }catch(FriendCryptException &e){
        return false;
    }

    if(!decode(dataOut, dataOut, len))
        return false;

    return true;
}


CryptWithKeccak::~CryptWithKeccak(){
    if(iv_)
        delete[] iv_;
    delete rng_;
}

//"static" method

//class for help
CWKData::CWKData(long blockLen):kBlockSize(blockLen){
    key_ = nullptr;
    salt_ = nullptr;
}

bool CWKData::setKey(const uint8_t *key, long len){
    if(!key || len<kMinLen)
        return false;

    if(!key_){
        key_ = new uint8_t[len];
        keyMaxLen_ = len;
    }else if(keyMaxLen_ < len){
        delete[] key_;
        key_ = new uint8_t[len];
        keyMaxLen_ = len;
    }

    std::memcpy(key_, key, len);
    keyLen_ = len;
    return true;
}

bool CWKData::setSalt(const uint8_t *salt, long len){
    if(!salt || len<kMinLen)
        return false;

    if(!salt_){
        salt_ = new uint8_t[len];
        saltMaxLen_ = len;
    }else if(saltMaxLen_ < len){
        delete[] salt_;
        salt_ = new uint8_t[len];
        saltMaxLen_ = len;
    }

    std::memcpy(salt_, salt, len);
    saltLen_ = len;
    return true;
}

CWKData::~CWKData(){
    if(key_)
        delete[] key_;
    if(salt_)
        delete[] salt_;
}


}//namespace
