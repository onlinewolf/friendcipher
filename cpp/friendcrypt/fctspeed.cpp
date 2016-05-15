/*
friendcrypt::test
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
#include "fctspeed.h"
#include "fccrypt.h"
#include "fcmixer.h"
#include "fckeccak.h"
#include "fcrng.h"

namespace friendcrypt{
namespace test{

namespace{//anonymous namespace for help

static const uint64_t kDifferent = 1000000; //us

uint64_t cryptSpeedCalc(bool enc, bool crazy, CryptWithKeccak &crypt, const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!dataIn || !dataOut || len<=0)
        return 1L;

    uint64_t results = 0L;

    for(int i=0; i<kSpeedTestTimes; i++){
        if(enc){
            if(crazy){
                auto start = std::chrono::high_resolution_clock::now();
                crypt.encryptCrazy(dataIn, dataOut, len);
                auto finish = std::chrono::high_resolution_clock::now();
                results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
            }else{
                auto start = std::chrono::high_resolution_clock::now();
                crypt.encrypt(dataIn, dataOut, len);
                auto finish = std::chrono::high_resolution_clock::now();
                results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
            }
        }else{
            if(crazy){
                auto start = std::chrono::high_resolution_clock::now();
                crypt.decryptCrazy(dataIn, dataOut, len);
                auto finish = std::chrono::high_resolution_clock::now();
                results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
            }else{
                auto start = std::chrono::high_resolution_clock::now();
                crypt.decrypt(dataIn, dataOut, len);
                auto finish = std::chrono::high_resolution_clock::now();
                results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
            }
        }
    }

    return results / kSpeedTestTimes;
}

uint64_t mixSpeedCalc(bool enc, bool crazy, MixWithKeccak &mixer, const uint8_t *dataIn, uint8_t *dataOut, int len){
    if(!dataIn || !dataOut || len<=0)
        return 1L;

    uint64_t results = 0L;

    for(int i=0; i<kSpeedTestTimes; i++){
        if(enc){
            if(crazy){
                auto start = std::chrono::high_resolution_clock::now();
                mixer.crazyMix(dataIn, dataOut, len);
                auto finish = std::chrono::high_resolution_clock::now();
                results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
            }else{
                auto start = std::chrono::high_resolution_clock::now();
                mixer.mix(dataIn, dataOut, len, 0);
                auto finish = std::chrono::high_resolution_clock::now();
                results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
            }
        }else{
            if(crazy){
                auto start = std::chrono::high_resolution_clock::now();
                mixer.reverseCrazyMix(dataIn, dataOut, len);
                auto finish = std::chrono::high_resolution_clock::now();
                results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
            }else{
                auto start = std::chrono::high_resolution_clock::now();
                mixer.reverseMix(dataIn, dataOut, len, 0);
                auto finish = std::chrono::high_resolution_clock::now();
                results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
            }
        }
    }

    return results / kSpeedTestTimes;
}

}//anonymous namespace for help



uint64_t cryptSpeed(bool enc, bool crazy, int bitLen, const uint8_t *dataIn, uint8_t *dataOut, int len, const uint8_t *key, int keyLen, const uint8_t* iv, int ivLen){
    if(!dataIn || !dataOut || len<=0 || !key || keyLen<=0 || !keccakBitLenCheck(bitLen))
        return 0L;

    CryptWithKeccak crypt(bitLen);
    if(!iv || ivLen<=0){
        crypt.createIV();
    }else{
        crypt.setIV(iv, ivLen);
    }
    crypt.setKey(key, keyLen);
    return (len*kDifferent)/cryptSpeedCalc(enc, crazy, crypt, dataIn, dataOut, len);
}


uint64_t mixSpeed(bool enc, bool crazy, int bitLen, const uint8_t *dataIn, uint8_t *dataOut, int len, const uint8_t *key, int keyLen, const uint8_t* iv, int ivLen){
    if(!dataIn || !dataOut || len<=0 || !key || keyLen<=0 || !iv || ivLen<=0 || !keccakBitLenCheck(bitLen))
        return 0L;

    MixWithKeccak mixer(bitLen);
    mixer.init(key, keyLen, iv, ivLen);
    return (len*kDifferent)/mixSpeedCalc(enc, crazy, mixer, dataIn, dataOut, len);
}

uint64_t keccakSpeed(int bitLen, const uint8_t *dataIn, int len, uint8_t *dataOut){
    if(!keccakBitLenCheck(bitLen) || !dataIn || len <= 0 || !dataOut)
        return 0L;

    uint64_t results = 0L;
    Keccak hash(bitLen);

    for(int i=0; i<kSpeedTestTimes; i++){
        auto start = std::chrono::high_resolution_clock::now();
        hash.update(dataIn, len);
        hash.finish(dataOut);
        auto finish = std::chrono::high_resolution_clock::now();
        results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
    }

    return (len*kDifferent*kSpeedTestTimes)/(results == 0L ? 1L : results);
}

uint64_t rngSpeed(int bitLen, const uint8_t *key, int keyLen, const uint8_t *iv, int ivLen, uint8_t *out, int outLen){
    if(!out || outLen<=0 || !key || keyLen<=0 || !keccakBitLenCheck(bitLen))
        return 0L;

    uint64_t results = 0L;
    Rng rng(bitLen);
    rng.init(key, keyLen, iv, ivLen);
    for(int i=0; i<kSpeedTestTimes; i++){
        auto start = std::chrono::high_resolution_clock::now();
        for(int x=0; x<outLen; x++)
            out[x] = rng.random8bit();
        auto finish = std::chrono::high_resolution_clock::now();
        results += std::chrono::duration_cast<std::chrono::microseconds>(finish-start).count();
    }

    return (outLen*kDifferent*kSpeedTestTimes)/(results == 0L ? 1L : results);
}


}//namespace
}//namespace
