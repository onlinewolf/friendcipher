#ifndef FRIENDCRYPTEXCEPTION_H
#define FRIENDCRYPTEXCEPTION_H
#include <exception>

namespace friendcrypt{

/**
 * @brief The FriendCryptException class
 * Exception for FriendCrypt
 */
class FriendCryptException: public std::exception{
    int what_;
public:
    FriendCryptException();
    explicit FriendCryptException(int what);
    FriendCryptException(const FriendCryptException& other);
    friend bool operator==(const FriendCryptException& lhs, const FriendCryptException& rhs);
    friend bool operator!=(const FriendCryptException& lhs, const FriendCryptException& rhs);
    virtual ~FriendCryptException();

    FriendCryptException(FriendCryptException&& other)=delete;
    FriendCryptException& operator=(const FriendCryptException&)=delete;
    FriendCryptException& operator=(FriendCryptException&& other)=delete;

};

extern FriendCryptException defaultException;
extern FriendCryptException invalidArgsExc;

}
#endif // FRIENDCRYPTEXCEPTION_H
