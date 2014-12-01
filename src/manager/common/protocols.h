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
 *
 * @file        protocols.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This file contains list of all protocols suported by Central
 *              Key Manager.
 */
#pragma once

#include <stdexcept>
#include <string>

#include <ckm/ckm-type.h>

#include <dpl/exception.h>
#include <dpl/serialization.h>

namespace CKM {

extern char const * const SERVICE_SOCKET_ECHO;
extern char const * const SERVICE_SOCKET_CKM_CONTROL;
extern char const * const SERVICE_SOCKET_CKM_STORAGE;
extern char const * const SERVICE_SOCKET_OCSP;

enum class ControlCommand : int {
    UNLOCK_USER_KEY,
    LOCK_USER_KEY,
    REMOVE_USER_DATA,
    CHANGE_USER_PASSWORD,
    RESET_USER_PASSWORD,
    REMOVE_APP_DATA,
    UPDATE_CC_MODE,
    SET_PERMISSION
    // for backward compatibility append new at the end
};

enum class LogicCommand : int {
    GET,
    GET_LIST,
    SAVE,
    REMOVE,
    CREATE_KEY_PAIR_RSA,
    CREATE_KEY_PAIR_ECDSA,
    GET_CHAIN_CERT,
    GET_CHAIN_ALIAS,
    CREATE_SIGNATURE,
    VERIFY_SIGNATURE,
    CREATE_KEY_PAIR_DSA,
    SET_PERMISSION
    // for backward compatibility append new at the end
};

class DBDataType {
public:
    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, OutOfRange)
    };

    enum DataType {
        KEY_RSA_PUBLIC,
        KEY_RSA_PRIVATE,
        KEY_ECDSA_PUBLIC,
        KEY_ECDSA_PRIVATE,
        KEY_DSA_PUBLIC,
        KEY_DSA_PRIVATE,
        KEY_AES,
        CERTIFICATE,
        BINARY_DATA,
        // Special types to support database,
        DB_FIRST = KEY_RSA_PUBLIC,
        DB_LAST  = BINARY_DATA,
        DB_KEY_FIRST = KEY_RSA_PUBLIC,
        DB_KEY_LAST  = KEY_AES,
    };

    DBDataType()
      : m_dataType(BINARY_DATA)
    {}

    DBDataType(DataType data)
      : m_dataType(data)
    {
        if (!isInRange(data))
            ThrowMsg(Exception::OutOfRange, "Invalid conversion from DataType to DBDataType");
    }

    explicit DBDataType(KeyType key) {
        switch(key) {
        case KeyType::KEY_RSA_PUBLIC:    m_dataType = DBDataType::KEY_RSA_PUBLIC;    break;
        case KeyType::KEY_RSA_PRIVATE:   m_dataType = DBDataType::KEY_RSA_PRIVATE;   break;
        case KeyType::KEY_DSA_PUBLIC:    m_dataType = DBDataType::KEY_DSA_PUBLIC;    break;
        case KeyType::KEY_DSA_PRIVATE:   m_dataType = DBDataType::KEY_DSA_PRIVATE;   break;
        case KeyType::KEY_ECDSA_PUBLIC:  m_dataType = DBDataType::KEY_ECDSA_PUBLIC;  break;
        case KeyType::KEY_ECDSA_PRIVATE: m_dataType = DBDataType::KEY_ECDSA_PRIVATE; break;
        case KeyType::KEY_AES:           m_dataType = DBDataType::KEY_AES;           break;
        default:
            ThrowMsg(Exception::OutOfRange, "Invalid conversion from KeyType to DBDataType");
        }
    }

    explicit DBDataType(int data)
      : m_dataType(static_cast<DataType>(data))
    {
        if (!isInRange(data))
            ThrowMsg(Exception::OutOfRange, "Invalid conversion from int to DBDataType");
    }

    DBDataType(const DBDataType &) = default;
    DBDataType& operator=(const DBDataType &) = default;

    operator int () const {
        return static_cast<int>(m_dataType);
    }

    operator KeyType () const {
        switch(m_dataType) {
        case DBDataType::KEY_RSA_PUBLIC: return KeyType::KEY_RSA_PUBLIC;
        case DBDataType::KEY_RSA_PRIVATE: return KeyType::KEY_RSA_PRIVATE;
        case DBDataType::KEY_DSA_PUBLIC: return KeyType::KEY_DSA_PUBLIC;
        case DBDataType::KEY_DSA_PRIVATE: return KeyType::KEY_DSA_PRIVATE;
        case DBDataType::KEY_ECDSA_PRIVATE: return KeyType::KEY_ECDSA_PRIVATE;
        case DBDataType::KEY_ECDSA_PUBLIC: return KeyType::KEY_ECDSA_PUBLIC;
        case DBDataType::KEY_AES: return KeyType::KEY_AES;
        default:
            ThrowMsg(Exception::OutOfRange, "Invalid conversion from DBDataType to KeyType");
        }
    }

    bool operator==(const DBDataType &second) const {
        return m_dataType == second.m_dataType;
    }

    bool isKey() const {
        if (DB_KEY_FIRST <= m_dataType && DB_KEY_LAST >= m_dataType)
            return true;
        return false;
    }

    bool isKeyPrivate() const {
        switch (m_dataType) {
        case KEY_RSA_PRIVATE:
        case KEY_DSA_PRIVATE:
        case KEY_ECDSA_PRIVATE:
              return true;
        default:
              return false;
        }
    }

    bool isKeyPublic() const {
        switch (m_dataType) {
        case KEY_RSA_PUBLIC:
        case KEY_DSA_PUBLIC:
        case KEY_ECDSA_PUBLIC:
              return true;
        default:
              return false;
        }
    }

    bool isCertificate() const {
        return m_dataType == CERTIFICATE;
    }

    bool isBinaryData() const {
        return m_dataType == BINARY_DATA;
    }

    static bool isInRange(int data) {
        if (data < static_cast<int>(DB_FIRST))
            return false;
        if (data > static_cast<int>(DB_LAST))
            return false;
        return true;
    }

    // it's not virtual with a reason!
    ~DBDataType(){}

private:
    DataType m_dataType;
};

// (client side) Alias = (service side) Label::Name
extern char const * const LABEL_NAME_SEPARATOR;
typedef std::string Name;
typedef std::vector<std::pair<Label, Name> > LabelNameVector;


const char* toDBPermission(Permission access_right_type);
Permission toPermission(const std::string &input_DB_data);

class IStream;

struct PolicySerializable : public Policy, ISerializable {
    PolicySerializable() {};
    explicit PolicySerializable(const Policy &policy) : Policy(policy) {}
    explicit PolicySerializable(IStream &stream) {
        Deserialization::Deserialize(stream, password);
        Deserialization::Deserialize(stream, extractable);
    }
    void Serialize(IStream &stream) const {
        Serialization::Serialize(stream, password);
        Serialization::Serialize(stream, extractable);
    }
};

} // namespace CKM

