/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 * @file        crypto-logic.h
 * @author      Sebastian Grabowski (s.grabowski@samsung.com)
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Crypto module implementation.
 */
#pragma once

#include <map>
#include <ckm/ckm-type.h>
#include <db-crypto.h>

namespace CKM {

class CryptoLogic {
public:
    CryptoLogic();
    CryptoLogic(const CryptoLogic &second) = delete;
    CryptoLogic(CryptoLogic &&second);
    CryptoLogic& operator=(CryptoLogic &&second);
    CryptoLogic& operator=(const CryptoLogic &second) = delete;

    virtual ~CryptoLogic(){}

    void decryptRow(const Password &password, DB::Row &row);
    void encryptRow(const Password &password, DB::Row &row);

    bool haveKey(const Label &smackLabel);
    void pushKey(const Label &smackLabel,
                 const RawBuffer &applicationKey);
    void removeKey(const Label &smackLabel);

private:
    static const int ENCR_BASE64 =   1 << 0;
    static const int ENCR_APPKEY =   1 << 1;
    static const int ENCR_PASSWORD = 1 << 2;

    std::map<Label, RawBuffer> m_keyMap;

    RawBuffer generateRandIV() const;
    RawBuffer passwordToKey(const Password &password,
                            const RawBuffer &salt,
                            size_t keySize) const;

    void decBase64(RawBuffer &data);
    void encBase64(RawBuffer &data);
    bool equalDigests(RawBuffer &dig1, RawBuffer &dig2);
};

} // namespace CKM

