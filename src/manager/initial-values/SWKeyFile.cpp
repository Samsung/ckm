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
 * @file        SWKeyFile.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       SWKeyFile class implementation.
 */

#include <iostream>
#include <SWKeyFile.h>
#include <BufferHandler.h>
#include <EncodingType.h>
#include <sw-backend/obj.h>
#include <dpl/log/log.h>

namespace {
const int          XML_SW_KEY_CURRENT_VERSION   = 1;
const char * const XML_TAG_DEVICE_KEY           = "DeviceKey";
const char * const XML_TAG_RSA_KEY              = "RSAPrivateKey";
const char * const XML_TAG_PEM                  = "PEM";
const char * const XML_TAG_DER                  = "DERBase64";
const char * const XML_TAG_BASE64               = "Base64";
const char * const XML_ATTR_VERSION             = "version";
}

namespace CKM {
namespace InitialValues {

SWKeyFile::SWKeyFile(const std::string &XML_filename)
        : m_parser(XML_filename),
          m_header(std::make_shared<HeaderHandler>(*this)),
          m_RSAKeyHandler(std::make_shared<RSAKeyHandler>(*this))
{
    m_parser.RegisterErrorCb(SWKeyFile::Error);
    m_parser.RegisterElementCb(XML_TAG_DEVICE_KEY,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_header;
            },
            [this](const XML::Parser::ElementHandlerPtr &) {});
}

void SWKeyFile::registerElementListeners()
{
    m_parser.RegisterElementCb(XML_TAG_RSA_KEY,
            [this]() -> XML::Parser::ElementHandlerPtr
            {
                return m_RSAKeyHandler;
            },
            [this](const XML::Parser::ElementHandlerPtr &)
            {
                m_deviceKey = m_RSAKeyHandler->getPrivKey();
            });
}

void SWKeyFile::Error(const XML::Parser::ErrorType errorType,
                      const std::string & log_msg)
{
    switch(errorType)
    {
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

int SWKeyFile::Validate(const std::string &XSD_file)
{
    return m_parser.Validate(XSD_file);
}

int SWKeyFile::Parse()
{
    int ec = m_parser.Parse();
    if(!m_header || !m_header->isCorrectVersion()) {
        LogError("bypassing XML file: " << m_filename << " - wrong file version!");
        ec = XML::Parser::ERROR_INVALID_VERSION;
    }
    return ec;
}



SWKeyFile::RSAKeyHandler::RSAKeyHandler(SWKeyFile & parent)
  : m_parent(parent)
{}

void SWKeyFile::RSAKeyHandler::Characters(const std::string &data) {
    //m_encryptedKey.reserve(m_encryptedKey.size() + data.size());
    //m_encryptedKey.insert(m_encryptedKey.end(), data.begin(), data.end());
    std::copy(data.begin(), data.end(), std::back_inserter(m_encryptedKey));
}

void SWKeyFile::RSAKeyHandler::End() {
//    std::string trimmed = XML::trimEachLine(std::string(m_encryptedKey.begin(), m_encryptedKey.end()));

    Base64Decoder base64;
    base64.reset();
    base64.append(XML::removeWhiteChars(m_encryptedKey));
    base64.finalize();
    m_encryptedKey = base64.get();
};

Crypto::GObjShPtr SWKeyFile::RSAKeyHandler::getPrivKey() {
    return std::make_shared<Crypto::SW::AKey>(m_encryptedKey, DataType::KEY_RSA_PRIVATE);
}

SWKeyFile::HeaderHandler::HeaderHandler(SWKeyFile & parent)
    : m_version(-1), m_parent(parent) {}
void SWKeyFile::HeaderHandler::Start(const XML::Parser::Attributes & attr)
{
    // get key type
    if(attr.find(XML_ATTR_VERSION) != attr.end())
    {
        m_version = atoi(attr.at(XML_ATTR_VERSION).c_str());

        if(isCorrectVersion())
            m_parent.registerElementListeners();
    }
}
bool SWKeyFile::HeaderHandler::isCorrectVersion() const {
    return m_version == XML_SW_KEY_CURRENT_VERSION;
}

}
}
