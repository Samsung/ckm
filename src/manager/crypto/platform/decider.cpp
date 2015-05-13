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
 * @file       decider.cpp
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#include <dpl/log/log.h>

#include <crypto-backend.h>

#include <platform/decider.h>

#include <sw-backend/store.h>

namespace CKM {
namespace Crypto {

Decider::Decider()
  : m_swStore(new SW::Store(CryptoBackend::OpenSSL))
{}

GStore& Decider::getStore(const Token &) {
    // This the place where we should choose backend bases on token information.
    if (!m_swStore) {
        LogError("No backend available.");
        ThrowMsg(CKM::Crypto::Exception::Base, "No backend available.");
    }
    return *m_swStore;
};

CryptoBackend Decider::chooseCryptoBackend(DataType, const Policy &) const {
    return CryptoBackend::OpenSSL;
}

} // namespace Crypto
} // namespace CKM

