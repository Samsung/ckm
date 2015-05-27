/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <dpl/log/log.h>

#include <generic-backend/exception.h>
#include <tz-backend/key.h>
#include <tz-backend/store.h>

namespace CKM {
namespace Crypto {
namespace TZ {

Store::Store(CryptoBackend backendId)
  : GStore(backendId)
{}

GKeyShPtr Store::getKey(const Token &) {
    LogError("Trust zone backend is not implemented!");
    ThrowMsg(Exception::Base, "Trust zone backend is not implemented!");
}

TokenPair Store::generateAKey(const CryptoAlgorithm &) {
    LogError("Trust zone backend is not implemented!");
    ThrowMsg(Exception::Base, "Trust zone backend is not implemented!");
}

Token Store::import(DataType, const RawBuffer &) {
    LogError("Trust zone backend is not implemented!");
    ThrowMsg(Exception::Base, "Trust zone backend is not implemented!");
}

} // namespace TZ
} // namespace Crypto
} // namespace CKM

