/*
FriendCryptException
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
#include "fcexception.h"

namespace friendcrypt{

FriendCryptException defaultException;
FriendCryptException invalidArgsExc(1);

FriendCryptException::FriendCryptException(){
    what_ = 0;
}

FriendCryptException::FriendCryptException(int what){
    what_ = what;
}

FriendCryptException::FriendCryptException(const FriendCryptException& other){
    what_ = other.what_;
}

bool operator==(const FriendCryptException& lhs, const FriendCryptException& rhs){
    return lhs.what_ == rhs.what_;
}

bool operator!=(const FriendCryptException& lhs, const FriendCryptException& rhs){
    return !(lhs == rhs);
}

FriendCryptException::~FriendCryptException(){}

}
