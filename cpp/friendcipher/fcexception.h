#ifndef FRIENDCRYPTEXCEPTION_H
#define FRIENDCRYPTEXCEPTION_H
#include <exception>

namespace friendcipher{

/**
 * @brief The FriendCryptException class
 * Exception for FriendCipher
 * (Thread safe!)
 */
class FriendCipherException: public std::exception{
    const int what_;
public:
    FriendCipherException();
    explicit FriendCipherException(int what);
    FriendCipherException(const FriendCipherException& other);
    /**
     * @brief operator ==
     * You can verify two exception with if
     * @param lhs Left
     * @param rhs Right
     * @return true if equal
     */
    friend bool operator==(const FriendCipherException& lhs, const FriendCipherException& rhs);
    /**
     * @brief operator !=
     * You can verify two exception with if
     * @param lhs Left
     * @param rhs Right
     * @return false if equal
     */
    friend bool operator!=(const FriendCipherException& lhs, const FriendCipherException& rhs);

    virtual ~FriendCipherException();

    //disabled
    FriendCipherException(FriendCipherException&& other)=delete;
    FriendCipherException& operator=(const FriendCipherException&)=delete;
    FriendCipherException& operator=(FriendCipherException&& other)=delete;

};

/**
 * @brief defaultException
 * Never use!
 */
extern FriendCipherException defaultException;

/**
 * @brief invalidArgsException
 * Use if arguments are wrong.
 */
extern FriendCipherException invalidArgsException;

}//namespace
#endif // FRIENDCRYPTEXCEPTION_H
