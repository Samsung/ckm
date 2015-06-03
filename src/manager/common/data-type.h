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
 * @file       data-type.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <ckm/ckm-type.h>
#include <dpl/exception.h>
#include <symbol-visibility.h>

namespace CKM {

class COMMON_API DataType {
public:
    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, OutOfRange)
    };

    enum Type {
        KEY_RSA_PUBLIC,
        KEY_RSA_PRIVATE,
        KEY_ECDSA_PUBLIC,
        KEY_ECDSA_PRIVATE,
        KEY_DSA_PUBLIC,
        KEY_DSA_PRIVATE,
        KEY_AES,
        CERTIFICATE,
        BINARY_DATA,

        CHAIN_CERT_0,
        CHAIN_CERT_1,
        CHAIN_CERT_2,
        CHAIN_CERT_3,
        CHAIN_CERT_4,
        CHAIN_CERT_5,
        CHAIN_CERT_6,
        CHAIN_CERT_7,
        CHAIN_CERT_8,
        CHAIN_CERT_9,
        CHAIN_CERT_10,
        CHAIN_CERT_11,
        CHAIN_CERT_12,
        CHAIN_CERT_13,
        CHAIN_CERT_14,
        CHAIN_CERT_15,

        // Special types to support database,
        DB_KEY_FIRST = KEY_RSA_PUBLIC,
        DB_KEY_LAST  = KEY_AES,
        DB_CHAIN_FIRST = CHAIN_CERT_0,
        DB_CHAIN_LAST = CHAIN_CERT_15,
        DB_FIRST = KEY_RSA_PUBLIC,
        DB_LAST  = CHAIN_CERT_15,
    };

    DataType();
    DataType(Type data);
    explicit DataType(int data);
    explicit DataType(KeyType key);
    explicit DataType(AlgoType algorithmType);
    DataType(const DataType &) = default;
    DataType& operator=(const DataType &) = default;

    operator int () const;
    operator KeyType () const;
    bool operator==(const DataType &second) const;

    bool isKey() const;
    bool isSKey() const;
    bool isChainCert() const;
    bool isKeyPrivate() const;
    bool isKeyPublic() const;
    bool isCertificate() const;
    bool isBinaryData() const;

    static bool isInRange(int data);
    static DataType getChainDatatype(unsigned int index);

    // it's not virtual for a reason!
    ~DataType(){}

private:
    Type m_dataType;
};

} // namespace CKM
