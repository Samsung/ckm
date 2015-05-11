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
 * @file       data-type.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <data-type.h>

namespace CKM
{

DataType::DataType()
  : m_dataType(BINARY_DATA)
{}

DataType::DataType(Type data)
  : m_dataType(data)
{
    if (!isInRange(data))
        ThrowMsg(Exception::OutOfRange, "Invalid conversion from DataType to DBDataType");
}

DataType::DataType(KeyType key) {
    switch(key) {
    case KeyType::KEY_RSA_PUBLIC:    m_dataType = DataType::KEY_RSA_PUBLIC;    break;
    case KeyType::KEY_RSA_PRIVATE:   m_dataType = DataType::KEY_RSA_PRIVATE;   break;
    case KeyType::KEY_DSA_PUBLIC:    m_dataType = DataType::KEY_DSA_PUBLIC;    break;
    case KeyType::KEY_DSA_PRIVATE:   m_dataType = DataType::KEY_DSA_PRIVATE;   break;
    case KeyType::KEY_ECDSA_PUBLIC:  m_dataType = DataType::KEY_ECDSA_PUBLIC;  break;
    case KeyType::KEY_ECDSA_PRIVATE: m_dataType = DataType::KEY_ECDSA_PRIVATE; break;
    case KeyType::KEY_AES:           m_dataType = DataType::KEY_AES;           break;
    default:
        ThrowMsg(Exception::OutOfRange, "Invalid conversion from KeyType to DBDataType");
    }
}

DataType::DataType(int data)
  : m_dataType(static_cast<Type>(data))
{
    if (!isInRange(data))
        ThrowMsg(Exception::OutOfRange, "Invalid conversion from int to DBDataType");
}

DataType::operator int () const {
    return static_cast<int>(m_dataType);
}

DataType::operator KeyType () const {
    switch(m_dataType) {
    case DataType::KEY_RSA_PUBLIC: return KeyType::KEY_RSA_PUBLIC;
    case DataType::KEY_RSA_PRIVATE: return KeyType::KEY_RSA_PRIVATE;
    case DataType::KEY_DSA_PUBLIC: return KeyType::KEY_DSA_PUBLIC;
    case DataType::KEY_DSA_PRIVATE: return KeyType::KEY_DSA_PRIVATE;
    case DataType::KEY_ECDSA_PRIVATE: return KeyType::KEY_ECDSA_PRIVATE;
    case DataType::KEY_ECDSA_PUBLIC: return KeyType::KEY_ECDSA_PUBLIC;
    case DataType::KEY_AES: return KeyType::KEY_AES;
    default:
        ThrowMsg(Exception::OutOfRange, "Invalid conversion from DBDataType to KeyType");
    }
}

bool DataType::operator==(const DataType &second) const {
    return m_dataType == second.m_dataType;
}

bool DataType::isKey() const {
    if (DB_KEY_FIRST <= m_dataType && DB_KEY_LAST >= m_dataType)
        return true;
    return false;
}

bool DataType::isChainCert() const {
    if (DB_CHAIN_FIRST <= m_dataType && DB_CHAIN_LAST >= m_dataType)
        return true;
    return false;
}

bool DataType::isKeyPrivate() const {
    switch (m_dataType) {
    case KEY_RSA_PRIVATE:
    case KEY_DSA_PRIVATE:
    case KEY_ECDSA_PRIVATE:
          return true;
    default:
          return false;
    }
}

bool DataType::isKeyPublic() const {
    switch (m_dataType) {
    case KEY_RSA_PUBLIC:
    case KEY_DSA_PUBLIC:
    case KEY_ECDSA_PUBLIC:
          return true;
    default:
          return false;
    }
}

bool DataType::isCertificate() const {
    return m_dataType == CERTIFICATE;
}

bool DataType::isBinaryData() const {
    return m_dataType == BINARY_DATA;
}

bool DataType::isInRange(int data) {
    if (data < static_cast<int>(DB_FIRST))
        return false;
    if (data > static_cast<int>(DB_LAST))
        return false;
    return true;
}

DataType DataType::getChainDatatype(unsigned int index)
{
    DataType result(static_cast<int>(index) + DB_CHAIN_FIRST);

    if ( !result.isChainCert() )
        ThrowMsg(Exception::OutOfRange, "Certificate number is out of range");

    return result;
}

} // namespace CKM
