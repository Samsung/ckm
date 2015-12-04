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
#include <atomic>
#include <functional>
#include <thread>
#include <fstream>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <dpl/log/log.h>

namespace CKM {
namespace {

const char* DEV_HW_RANDOM_FILE = "/dev/hwrng";
const char* DEV_URANDOM_FILE = "/dev/urandom";
const size_t RANDOM_BUFFER_LEN = 32;

std::mutex* g_mutexes = NULL;

void lockingCallback(int mode, int type, const char*, int)
{
    if(!g_mutexes) {
        LogError("Openssl mutexes do not exist");
        return;
    }

    if (mode & CRYPTO_LOCK)
        g_mutexes[type].lock();
    else if (mode & CRYPTO_UNLOCK)
        g_mutexes[type].unlock();
}

unsigned long threadIdCallback() {
    std::hash<std::thread::id> hasher;
    return hasher(std::this_thread::get_id());
}

void opensslInstallLocks()
{
    g_mutexes = new std::mutex[CRYPTO_num_locks()];

    CRYPTO_set_id_callback(threadIdCallback);
    CRYPTO_set_locking_callback(lockingCallback);
}

void opensslUninstallLocks()
{
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    delete[] g_mutexes;
    g_mutexes = NULL;
}

} // namespace anonymous


void initOpenSsl() {
    // Loads all error strings (crypto and ssl)
    SSL_load_error_strings();

    /*
     * Initialize libcrypto (add all algorithms, digests & ciphers)
     * It also does the stuff from SSL_library_init() except for ssl_load_ciphers()
     */
    OpenSSL_add_all_algorithms(); // Can be optimized by using EVP_add_cipher instead

    /*
     *  Initialize libssl (OCSP uses it)
     *  SSL_library_init() == OpenSSL_add_ssl_algorithms()
     *  It always returns 1
     */
    SSL_library_init();

    // load default configuration (/etc/ssl/openssl.cnf)
    OPENSSL_config(NULL);

    // enable FIPS mode by default
    if(0 == FIPS_mode_set(1)) {
        LogWarning("Failed to set FIPS mode. Key-manager will be operated in non FIPS mode.");
    }

    /*
     * Initialize entropy
     * entropy sources - /dev/random,/dev/urandom(Default)
     */
    int ret = 0;

    std::ifstream ifile(DEV_HW_RANDOM_FILE);
    if(ifile.is_open())
        ret= RAND_load_file(DEV_HW_RANDOM_FILE, RANDOM_BUFFER_LEN);

    if(ret != RANDOM_BUFFER_LEN ){
        LogWarning("Error in HW_RAND file load");
        ret = RAND_load_file(DEV_URANDOM_FILE, RANDOM_BUFFER_LEN);

        if(ret != RANDOM_BUFFER_LEN)
            LogError("Error in U_RAND_file_load");
    }

    // Install locks for multithreading support
    opensslInstallLocks();
}

void deinitOpenSsl() {
    opensslUninstallLocks();
    CONF_modules_unload(1);
    EVP_cleanup();
    ERR_free_strings();
    deinitOpenSslThread();
}

void deinitOpenSslThread() {
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
}

namespace {
std::mutex cryptoInitMutex;

void initOpenSslAndDetach();

typedef void(*initFnPtr)();

// has to be atomic as storing function pointer is not an atomic operation on armv7l
std::atomic<initFnPtr> initFn (&initOpenSslAndDetach);

void initEmpty() {}

void initOpenSslAndDetach() {
    // DCLP
    std::lock_guard<std::mutex> lock(cryptoInitMutex);
    /*
     * We don't care about memory ordering here. Current thread will order it correctly and for
     * other threads only store matters. Also only one thread can be here at once because of lock.
     */
    if(initFn.load(std::memory_order_relaxed) != &initEmpty)
    {
        initOpenSsl();

        /*
         * Synchronizes with load. Everything that happened before this store in this thread is
         * visible to everything that happens after load in another thread. We switch to an empty
         * function here.
         */
        initFn.store(&initEmpty, std::memory_order_release);
    }
}

} // namespace anonymous

void initOpenSslOnce() {
    /*
     * Synchronizes with store. Everything that happened before store in another thread will be
     * visible in this thread after load.
     */
    initFn.load(std::memory_order_acquire)();
}

} /* namespace CKM */
