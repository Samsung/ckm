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
 * @file       gkey.h
 * @author     Bartłomiej Grzelewski (b.grzelewski@samsung.com)
 * @version    1.0
 */
#pragma once
#include <memory>

#include <ckm/ckm-raw-buffer.h>
#include <ckm/ckm-type.h>

#include <generic-backend/exception.h>

namespace CKM {
namespace Crypto {

class GKey {
protected:
    GKey(){}
public:
    virtual RawBuffer getBinary() {
        Throw(Exception::OperationNotSupported);
    }

    virtual RawBuffer encrypt(const CryptoAlgorithm &, const RawBuffer &) {
        Throw(Exception::OperationNotSupported);
    }

    virtual RawBuffer decrypt(const CryptoAlgorithm &, const RawBuffer &) {
        Throw(Exception::OperationNotSupported);
    }

    virtual RawBuffer sign(const CryptoAlgorithm &, const RawBuffer &) {
        Throw(Exception::OperationNotSupported);
    }

    virtual int verify(const CryptoAlgorithm &, const RawBuffer &, const RawBuffer &) {
        Throw(Exception::OperationNotSupported);
    }

    virtual ~GKey () {}
};

typedef std::shared_ptr<GKey> GKeyShPtr;

} // namespace Crypto
} // namespace CKM

