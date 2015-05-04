/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       store.cpp
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <memory>

#include <dpl/log/log.h>

#include <generic-backend/exception.h>
#include <sw-backend/key.h>
#include <sw-backend/store.h>

namespace CKM {
namespace Crypto {
namespace SW {

Id Store::getBackendId() const { return Id::OpenSSL; }

GKeyShPtr Store::getKey(const Token &token) {
    if (token.backendId != getBackendId()) {
        LogDebug("Decider choose wrong backend!");
        ThrowMsg(Exception::WrongBackend, "Decider choose wrong backend!");
    }

    switch (token.keyType) {
    case KeyType::KEY_RSA_PUBLIC:
    case KeyType::KEY_RSA_PRIVATE:
    case KeyType::KEY_DSA_PUBLIC:
    case KeyType::KEY_DSA_PRIVATE:
    case KeyType::KEY_ECDSA_PUBLIC:
    case KeyType::KEY_ECDSA_PRIVATE:
         return std::make_shared<AKey>(token.buffer, token.keyType);
    case KeyType::KEY_AES:
         return std::make_shared<SKey>(token.buffer, token.keyType);
    default:
         LogDebug(
            "This type of key is not supported by openssl backend: " << (int)token.keyType);
         ThrowMsg(Exception::KeyNotSupported,
            "This type of key is not supported by openssl backend: " << (int)token.keyType);
    }

}

Token Store::import(KeyType keyType, const RawBuffer &buffer) {
    Token token;
    token.buffer = buffer;
    token.keyType = keyType;
    token.backendId = getBackendId();
    return token;
}

} // namespace SW
} // namespace Crypto
} // namespace CKM

