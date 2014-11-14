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
 * @file       crypto.cpp
 * @author     Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version    1.0
 */

#include "crypto.h"
#include <mutex>

namespace CKM {

namespace {
bool isCryptoInitialized = false;
std::mutex cryptoInitMutex;
}

void initCryptoLib() {
    std::lock_guard<std::mutex> lock(cryptoInitMutex);
    if(!isCryptoInitialized)
    {
        isCryptoInitialized = true;
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_digests();
    }
}

} /* namespace CKM */
