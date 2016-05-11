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
    /**
     * @brief operator ==
     * You can verify two exception with if
     * @param lhs Left
     * @param rhs Right
     * @return true if equal
     */
    friend bool operator==(const FriendCryptException& lhs, const FriendCryptException& rhs);
    /**
     * @brief operator !=
     * You can verify two exception with if
     * @param lhs Left
     * @param rhs Right
     * @return false if equal
     */
    friend bool operator!=(const FriendCryptException& lhs, const FriendCryptException& rhs);
    virtual ~FriendCryptException();

    FriendCryptException(FriendCryptException&& other)=delete;
    FriendCryptException& operator=(const FriendCryptException&)=delete;
    FriendCryptException& operator=(FriendCryptException&& other)=delete;

};

extern FriendCryptException defaultException;
/**
 * @brief invalidArgsException
 * If arguments are wrong.
 */
extern FriendCryptException invalidArgsException;

}//namespace
#endif // FRIENDCRYPTEXCEPTION_H
