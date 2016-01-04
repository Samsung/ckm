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
 *
 *
 * @file        InitialValuesFile.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       InitialValuesFile class implementation.
 */

#include <iostream>
#include <InitialValuesFile.h>
#include <InitialValueHandler.h>
#include <BufferHandler.h>
#include <EncodingType.h>
#include <KeyHandler.h>
#include <CertHandler.h>
#include <DataHandler.h>
#include <EncodingType.h>
#include <sw-backend/obj.h>
#include <dpl/log/log.h>

namespace {
const int          XML_CURRENT_VERSION      = 1;
const char * const XML_TAG_INITIAL_VALUES   = "InitialValues";
const char * const XML_TAG_ENCRYPTION_KEY   = "EncryptionKey";
const char * const XML_TAG_KEY              = "Key";
const char * const XML_TAG_DATA             = "Data";
const char * const XML_TAG_CERT             = "Cert";
const char * const XML_TAG_PEM              = "PEM";
const char * const XML_TAG_DER              = "DER";
const char * const XML_TAG_ASCII            = "ASCII";
const char * const XML_TAG_BASE64           = "Base64";
const char * const XML_TAG_ENCRYPTED_DER    = "EncryptedDER";
const char * const XML_TAG_ENCRYPTED_ASCII  = "EncryptedASCII";
const char * const XML_TAG_ENCRYPTED_BINARY = "EncryptedBinary";
const char * const XML_TAG_PERMISSION       = "Permission";
const char * const XML_ATTR_VERSION         = "version";
}

namespace CKM {
namespace InitialValues {

InitialValuesFile::InitialValuesFile(const std::string &XML_filename,
                                     CKMLogic & db_logic)
        : m_parser(XML_filename), m_db_logic(db_logic),
          m_header(std::make_shared<HeaderHandler>(*this)),
          m_encryptionKeyHandler(std::make_shared<EncryptionKeyHandler>(*this))
{
    m_parser.RegisterErrorCb(InitialValuesFile::Error);
    m_parser.RegisterElementCb(XML_TAG_INITIAL_VALUES,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_header;
            },
            [this](const XML::Parser::ElementHandlerPtr &) {});
    m_parser.RegisterElementCb(XML_TAG_ENCRYPTION_KEY,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_encryptionKeyHandler;
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_encryptedAESkey = m_encryptionKeyHandler->getEncryptedKey();
            });
}

void InitialValuesFile::registerElementListeners()
{
    m_parser.RegisterElementCb(XML_TAG_KEY,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetObjectHandler(ObjectType::KEY, m_encryptedAESkey);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseObjectHandler(ObjectType::KEY);
            });
    m_parser.RegisterElementCb(XML_TAG_CERT,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetObjectHandler(ObjectType::CERT, m_encryptedAESkey);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseObjectHandler(ObjectType::CERT);
            });
    m_parser.RegisterElementCb(XML_TAG_DATA,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetObjectHandler(ObjectType::DATA, m_encryptedAESkey);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseObjectHandler(ObjectType::DATA);
            });

    m_parser.RegisterElementCb(XML_TAG_PEM,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetBufferHandler(EncodingType::PEM);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseBufferHandler(EncodingType::PEM);
            });
    m_parser.RegisterElementCb(XML_TAG_DER,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetBufferHandler(EncodingType::DER);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseBufferHandler(EncodingType::DER);
            });
    m_parser.RegisterElementCb(XML_TAG_ASCII,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetBufferHandler(EncodingType::ASCII);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseBufferHandler(EncodingType::ASCII);
            });
    m_parser.RegisterElementCb(XML_TAG_BASE64,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetBufferHandler(EncodingType::BASE64);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseBufferHandler(EncodingType::BASE64);
            });
    m_parser.RegisterElementCb(XML_TAG_ENCRYPTED_DER,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetBufferHandler(EncodingType::ENCRYPTED);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseBufferHandler(EncodingType::ENCRYPTED);
            });
    m_parser.RegisterElementCb(XML_TAG_ENCRYPTED_ASCII,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetBufferHandler(EncodingType::ENCRYPTED);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseBufferHandler(EncodingType::ENCRYPTED);
            });
    m_parser.RegisterElementCb(XML_TAG_ENCRYPTED_BINARY,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetBufferHandler(EncodingType::ENCRYPTED);
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleaseBufferHandler(EncodingType::ENCRYPTED);
            });
    m_parser.RegisterElementCb(XML_TAG_PERMISSION,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return GetPermissionHandler();
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                ReleasePermissionHandler();
            });
}

void InitialValuesFile::Error(const XML::Parser::ErrorType errorType,
                              const std::string & log_msg)
{
    switch (errorType) {
    case XML::Parser::VALIDATION_ERROR:
        LogWarning("validating error: " << log_msg);
        break;
    case XML::Parser::PARSE_WARNING:
        LogWarning("parsing warning: " << log_msg);
        break;
    case XML::Parser::PARSE_ERROR:
        LogWarning("parsing error: " << log_msg);
        break;
    }
}

int InitialValuesFile::Validate(const std::string &XSD_file)
{
    return m_parser.Validate(XSD_file);
}

int InitialValuesFile::Parse()
{
    int ec = m_parser.Parse();
    if (!m_header || !m_header->isCorrectVersion()) {
        LogError("bypassing XML file: " << m_filename << " - wrong file version!");
        ec = XML::Parser::ERROR_INVALID_VERSION;
    }
    return ec;
}

XML::Parser::ElementHandlerPtr InitialValuesFile::GetObjectHandler(ObjectType type,
                                                                   const CKM::RawBuffer &encryptedKey)
{
    switch (type) {
    case KEY:
        m_currentHandler = std::make_shared<KeyHandler>(m_db_logic, encryptedKey);
        break;

    case CERT:
        m_currentHandler = std::make_shared<CertHandler>(m_db_logic, encryptedKey);
        break;

    case DATA:
        m_currentHandler = std::make_shared<DataHandler>(m_db_logic, encryptedKey);
        break;

    default:
        m_currentHandler.reset();
        break;
    }

    return m_currentHandler;
}

void InitialValuesFile::ReleaseObjectHandler(ObjectType /*type*/)
{
    m_currentHandler.reset();
}




XML::Parser::ElementHandlerPtr InitialValuesFile::GetBufferHandler(EncodingType type)
{
    if ( !m_currentHandler )
        return XML::Parser::ElementHandlerPtr();

    return m_currentHandler->CreateBufferHandler(type);
}
void InitialValuesFile::ReleaseBufferHandler(EncodingType /*type*/)
{
}


XML::Parser::ElementHandlerPtr InitialValuesFile::GetPermissionHandler()
{
    if ( !m_currentHandler )
        return XML::Parser::ElementHandlerPtr();

    return m_currentHandler->CreatePermissionHandler();
}
void InitialValuesFile::ReleasePermissionHandler()
{
}


InitialValuesFile::EncryptionKeyHandler::EncryptionKeyHandler(InitialValuesFile & parent) : m_parent(parent) {}
void InitialValuesFile::EncryptionKeyHandler::Characters(const std::string &data)
{
    m_encryptedKey.reserve(m_encryptedKey.size() + data.size());
    m_encryptedKey.insert(m_encryptedKey.end(), data.begin(), data.end());
};

void InitialValuesFile::EncryptionKeyHandler::End()
{
    std::string trimmed = XML::trimEachLine(std::string(m_encryptedKey.begin(), m_encryptedKey.end()));
    Base64Decoder base64;
    base64.reset();
    base64.append(RawBuffer(trimmed.begin(), trimmed.end()));
    base64.finalize();
    m_encryptedKey = base64.get();
};

CKM::RawBuffer InitialValuesFile::EncryptionKeyHandler::getEncryptedKey() const
{
    return m_encryptedKey;
}

InitialValuesFile::HeaderHandler::HeaderHandler(InitialValuesFile & parent) :
    m_version(-1), m_parent(parent)
{
}

void InitialValuesFile::HeaderHandler::Start(const XML::Parser::Attributes & attr)
{
    // get key type
    if (attr.find(XML_ATTR_VERSION) != attr.end()) {
        m_version = atoi(attr.at(XML_ATTR_VERSION).c_str());

        if (isCorrectVersion())
            m_parent.registerElementListeners();
    }
}
bool InitialValuesFile::HeaderHandler::isCorrectVersion() const
{
    return m_version == XML_CURRENT_VERSION;
}

}
}
