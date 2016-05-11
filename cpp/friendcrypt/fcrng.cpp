#include "fcrng.h"
#include "fcexception.h"
#include "fckeccak.h"

namespace friendcrypt{

Rng::Rng(const uint8_t *seed, long seedLen, const uint8_t *salt, long saltLen): hash_(kMdBitLen){
    if(!seed || seedLen <= 0)
        throw invalidArgsException;

    hash_.update(seed, seedLen);

    if(salt && saltLen > 0)
        hash_.update(salt, saltLen);

    hash_.finish(seed_);

    hash_.update(seed_, kMdLen);
    hash_.update(seed_, kMdLen);
    hash_.finish(randMd_);
    p_ = 0;
}

void Rng::reSeed(const uint8_t *seed, long seedLen){
    if(!seed || seedLen <= 0)
        throw invalidArgsException;

    hash_.update(seed_, kMdLen);
    hash_.update(seed, seedLen);
    hash_.finish(seed_);

    hash_.update(seed_, kMdLen);
    hash_.update(seed_, kMdLen);
    hash_.finish(randMd_);
}

uint8_t Rng::random8bit(){
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
    uint32_t temp;
    uint8_t * t = (uint8_t *)&temp;
    for(int i=0; i<4; i++)
        t[i] = random8bit();

    return temp;
}

}//namespace
