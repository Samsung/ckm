/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file       crypto-init.cpp
 * @author     Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version    1.0
 */

#include "crypto-init.h"
#include <mutex>
#include <openssl/evp.h>
#include <atomic>

namespace CKM {

namespace {
std::mutex cryptoInitMutex;

void initOpenSSL();

typedef void(*initFnPtr)();

// has to be atomic as storing function pointer is not an atomic operation on armv7l
std::atomic<initFnPtr> initFn (&initOpenSSL);

void initEmpty() {}

void initOpenSSL() {
    // DCLP
    std::lock_guard<std::mutex> lock(cryptoInitMutex);
    /*
     * We don't care about memory ordering here. Current thread will order it correctly and for
     * other threads only store matters. Also only one thread can be here at once because of lock.
     */
    if(initFn.load(std::memory_order_relaxed) != &initEmpty)
    {
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_digests();

        /*
         * Synchronizes with load. Everything that happened before this store in this thread is
         * visible to everything that happens after load in another thread. We switch to an empty
         * function here.
         */
        initFn.store(&initEmpty, std::memory_order_release);
    }
}

} // namespace anonymous

void initCryptoLib() {
    /*
     * Synchronizes with store. Everything that happened before store in another thread will be
     * visible in this thread after load.
     */
    initFn.load(std::memory_order_acquire)();
}

} /* namespace CKM */
