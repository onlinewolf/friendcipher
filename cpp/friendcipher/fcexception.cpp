/*
friendcipher::FriendCryptException
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
#include "fcexception.h"

namespace friendcipher{

FriendCipherException defaultException;
FriendCipherException invalidArgsException(1);

FriendCipherException::FriendCipherException():what_(0){
}

FriendCipherException::FriendCipherException(int what):what_(what){
}

FriendCipherException::FriendCipherException(const FriendCipherException &other):what_(other.what_){
}

bool operator==(const FriendCipherException& lhs, const FriendCipherException& rhs){
    return lhs.what_ == rhs.what_;
}

bool operator!=(const FriendCipherException& lhs, const FriendCipherException& rhs){
    return !(lhs == rhs);
}

FriendCipherException::~FriendCipherException(){}

}
