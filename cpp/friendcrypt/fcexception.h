#ifndef FRIENDCRYPTEXCEPTION_H
#define FRIENDCRYPTEXCEPTION_H
#include <exception>

namespace friendcrypt{

/**
 * @brief The FriendCryptException class
 * Exception for FriendCrypt
 * (Thread safe!)
 */
class FriendCryptException: public std::exception{
    const int what_;
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

    //disabled
    FriendCryptException(FriendCryptException&& other)=delete;
    FriendCryptException& operator=(const FriendCryptException&)=delete;
    FriendCryptException& operator=(FriendCryptException&& other)=delete;

};

/**
 * @brief defaultException
 * Never use!
 */
extern FriendCryptException defaultException;

/**
 * @brief invalidArgsException
 * Use if arguments are wrong.
 */
extern FriendCryptException invalidArgsException;

}//namespace
#endif // FRIENDCRYPTEXCEPTION_H
