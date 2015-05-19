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
 * @file       gstore.h
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once

#include <memory>

#include <generic-backend/exception.h>
#include <generic-backend/gkey.h>
#include <ckm/ckm-type.h>
#include <crypto-backend.h>
#include <token.h>

namespace CKM {
namespace Crypto {

class GStore {
public:
    virtual GKeyShPtr getKey(const Token &) { Throw(Exception::OperationNotSupported); }
    virtual TokenPair generateAKey(const CryptoAlgorithm &) { Throw(Exception::OperationNotSupported); }
    virtual Token generateSKey(const CryptoAlgorithm &) { Throw(Exception::OperationNotSupported); }
    virtual Token import(DataType, const RawBuffer &) { Throw(Exception::OperationNotSupported); }
    virtual void destroy(const Token &) { Throw(Exception::OperationNotSupported); }
    virtual ~GStore() {}

protected:
    explicit GStore(CryptoBackend backendId) : m_backendId(backendId) {}

    CryptoBackend m_backendId;
};

} // namespace Crypto
} // namespace CKM

