/*
friendcipher::CryptWithRng
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

URL: https://github.com/onlinewolf/friendcipher
*/
#include <cstring>
#include <ctime>
#include "fccipher.h"
#include "fcexception.h"
#include "fckeccak.h"

namespace friendcipher{

//class
CryptWithRng::CryptWithRng(int bitLen):
        kMdLen(bitLen/8), kMdBitLen(bitLen), mixer_(bitLen), rng_(bitLen), ivRng_(bitLen){
    if(!keccakBitLenCheck(bitLen))
        throw invalidArgsException;

    iv_ = nullptr;
    time_t ti = time(NULL);//4 byte or 8 byte size
    ivRng_.reSeed(reinterpret_cast<uint8_t*>(&ti), sizeof(ti));
}

void CryptWithRng::ivCheck(int len){
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

void CryptWithRng::createIV(){
    ivCheck(kMdLen);
    ivLen_ = kMdLen;

    for(int i=0; i<kMdLen; i++)
        iv_[i] = ivRng_.random8bit();
}

int CryptWithRng::getIVLen(){
    if(!iv_)
        return 0;

    return ivLen_;
}

bool CryptWithRng::setIV(const uint8_t *iv, int len){
    if(!iv || len < helper_.kMinLen)
        return false;

    ivCheck(len);
    ivLen_ = len;

    std::memcpy(iv_, iv, len);
    return true;
}

bool CryptWithRng::getIV(uint8_t *iv){
    if(!iv)
        return false;

    std::memcpy(iv, iv_, ivLen_);
    return true;
}

bool CryptWithRng::setKey(const uint8_t *key, int len){
    return helper_.setKey(key, len);
}


bool CryptWithRng::encode(const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_)
        return false;

        rng_.init(iv_, ivLen_, helper_.key_, helper_.keyLen_);
        for(int i=0; i<len; i++)
            dataOut[i] = dataIn[i] ^ rng_.random8bit();

    return true;
}

bool CryptWithRng::decode(const uint8_t *dataIn, uint8_t *dataOut, int len){
    return encode(dataIn, dataOut, len);
}


bool CryptWithRng::encrypt(const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_)
        return false;

    if(!encode(dataIn, dataOut, len))
        return false;

    mixer_.init(helper_.key_, helper_.keyLen_, iv_, ivLen_);

    if(!mixer_.mix(dataOut, dataOut, len, 0))
        return false;


    return true;
}


bool CryptWithRng::decrypt(const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_)
        return false;

    mixer_.init(helper_.key_, helper_.keyLen_, iv_, ivLen_);

    if(!mixer_.reverseMix(dataIn, dataOut, len, 0))
        return false;

    if(!decode(dataOut, dataOut, len))
        return false;

    return true;
}


bool CryptWithRng::encryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_)
        return false;

    if(!encode(dataIn, dataOut, len))
        return false;


    mixer_.init(helper_.key_, helper_.keyLen_, iv_, ivLen_);
    if(!mixer_.crazyMix(dataOut, dataOut, len))
        return false;


    return true;
}

bool CryptWithRng::decryptCrazy(const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!dataIn || !dataOut || len <= 0)
        return false;

    if(!iv_ || !helper_.key_)
        return false;


    mixer_.init(helper_.key_, helper_.keyLen_, iv_, ivLen_);
    if(!mixer_.reverseCrazyMix(dataIn, dataOut, len))
        return false;

    if(!decode(dataOut, dataOut, len))
        return false;

    return true;
}


CryptWithRng::~CryptWithRng(){
    if(iv_)
        delete[] iv_;
}

//"static" method

//class for help
CWKData::CWKData(){
    key_ = nullptr;
}

bool CWKData::setKey(const uint8_t *key, int len){
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

CWKData::~CWKData(){
    if(key_)
        delete[] key_;
}


}//namespace
