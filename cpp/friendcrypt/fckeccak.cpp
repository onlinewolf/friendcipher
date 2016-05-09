/*
friendcrypt::Keccak
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
#include <cstring>
#include "fckeccak.h"
#include "3rd/keccak.h"

namespace friendcrypt{

Keccak::Keccak(int mdLen){
    rsiz_ = 200 - 2 * mdLen;
    rsizw_ = rsiz_ / 8;
    mdLen_ = mdLen;
    forUpdate_ = new uint8_t[rsiz_];
    reset();
}

void Keccak::reset(){
    updatePos_ = 0;
    memset(forDigest_, 0, sizeof(forDigest_));
}

void Keccak::update(const uint8_t *data, int len){
    if(!data || len <= 0)
        return;

    int neg = 0;
    int i;
    for(i=0; i<len; i++){
        forUpdate_[updatePos_+i+neg] = data[i];
        if((updatePos_+i+neg) == rsiz_-1){
            updatePos_ = 0;
            for (int x = 0; x < rsizw_; x++)
                forDigest_[x] ^= ((uint64_t *)forUpdate_)[x];
            keccakf(forDigest_, kKeccakRounds);//3rd
            neg -= i+1;
        }
    }

    updatePos_ = updatePos_+i+neg;
}

void Keccak::finish(uint8_t *out){
    if(!out)
        return;

    if(updatePos_ != 0){
        forUpdate_[updatePos_++] = 1;
        memset(forUpdate_ + updatePos_, 0, rsiz_ - updatePos_);
        forUpdate_[rsiz_ - 1] |= 0x80;

        for (int i = 0; i < rsizw_; i++)
            forDigest_[i] ^= ((uint64_t *)forUpdate_)[i];

        keccakf(forDigest_, kKeccakRounds);//3rd
    }

    memcpy(out, forDigest_, mdLen_);
    reset();
}

Keccak::~Keccak(){
    delete[] forUpdate_;
}


}//namesapce
