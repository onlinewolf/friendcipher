#include "fcrng.h"
#include "fcexception.h"
#include "cstring"

namespace friendcrypt{

Rng::Rng(long bitLen): kMdBitLen(bitLen), kMdLen(bitLen/8), hash_(bitLen){
    if(!keccakBitLenCheck(bitLen))
        throw invalidArgsException;

    seed_ = new uint8_t[kMdLen];
    randMd_ = new uint8_t[kMdLen];
    init_ = false;
}

bool Rng::init(const uint8_t *seed, long seedLen, const uint8_t *salt, long saltLen){
    if(!seed || seedLen <= 0)
        return false;

    hash_.update(seed, seedLen);

    if(salt && saltLen > 0)
        hash_.update(salt, saltLen);

    hash_.finish(seed_);

    hash_.update(seed_, kMdLen);
    hash_.update(seed_, kMdLen);
    hash_.finish(randMd_);
    init_ = true;
    p_ = 0;

    return true;
}

bool Rng::isInited(){
    return init_;
}

bool Rng::reSeed(const uint8_t *seed, long seedLen){
    if(!seed || seedLen <= 0)
        return false;

    hash_.update(seed_, kMdLen);
    hash_.update(seed, seedLen);
    hash_.finish(seed_);

    hash_.update(seed_, kMdLen);
    hash_.update(seed_, kMdLen);
    hash_.finish(randMd_);
    init_ = true;
    p_ = 0;

    return true;
}

uint8_t Rng::random8bit(){
    if(!init_)
        return 0;

    if(p_ >= kMdLen){
        hash_.update(randMd_, kMdLen);
        hash_.update(seed_, kMdLen);
        hash_.finish(randMd_);
        p_ = 0;
    }
    uint8_t temp = randMd_[p_];
    p_++;
    return temp;
}

uint32_t Rng::random32bit(){
    if(!init_)
        return 0;

    uint32_t temp;
    uint8_t * t = (uint8_t *)&temp;
    for(int i=0; i<4; i++)
        t[i] = random8bit();

    return temp;
}

Rng::~Rng(){
    delete[] seed_;
    delete[] randMd_;
}

}//namespace
