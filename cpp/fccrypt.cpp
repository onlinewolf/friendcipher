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
#include "fccrypt.h"
#include "fcexception.h"
#include "3rd/keccak.h"

namespace friendcrypt{

//class
void CryptWithKeccak::creator(long blockSize){
    iv_ = new uint8_t[blockSize];
    saltAndPassAndIv_ = new uint8_t[kFullSize];
    memset(saltAndPassAndIv_, 0, kFullSize);
}

CryptWithKeccak::CryptWithKeccak(): kMaxBlockSize(64), kFullSize(64*3){
    creator(64);
}

CryptWithKeccak::CryptWithKeccak(long blockSize): kMaxBlockSize(blockSize), kFullSize(blockSize*3){
    if(blockSize <= 0 || blockSize > 64 || (blockSize % 32) != 0)
        throw invalidArgsException;
    creator(blockSize);
}

void CryptWithKeccak::useIV(){
    memcpy(&saltAndPassAndIv_[kMaxBlockSize*2], iv_, kMaxBlockSize);
}

void CryptWithKeccak::createIV(){
    std::srand(std::time(0));
    for(long i=0; i<kMaxBlockSize; i++){
        iv_[i] = std::rand() % 256;
    }
    useIV();
}

bool CryptWithKeccak::setIV(uint8_t *iv){
    if(!iv)
        return false;

    memcpy(iv_, iv, kMaxBlockSize);
    useIV();
    return true;
}

void CryptWithKeccak::getIV(uint8_t *iv){
    if(!iv)
        return;

    memcpy(iv, iv_, kMaxBlockSize);
}

CryptWithKeccak::~CryptWithKeccak(){
    delete[] iv_;
    delete[] saltAndPassAndIv_;
}

//"static" method
}
