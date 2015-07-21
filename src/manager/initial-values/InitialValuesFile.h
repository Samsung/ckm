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
 * @file        InitialValuesFile.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       InitialValuesFile class.
 */

#ifndef INITIALVALUESFILE_H_
#define INITIALVALUESFILE_H_

#include <parser.h>
#include <InitialValueHandler.h>
#include <ckm-logic.h>
#include <string>
#include <algorithm>
#include <cctype>
#include <xml-utils.h>
#include <base64.h>

namespace CKM {
namespace InitialValues {


class InitialValuesFile
{
public:
    InitialValuesFile(const std::string &XML_filename,
                      CKMLogic & db_logic);

    int Validate(const std::string &XSD_file);
    int Parse();

protected:
    enum ObjectType {
        KEY,
        CERT,
        DATA
    };

    XML::Parser::ElementHandlerPtr GetObjectHandler(ObjectType type, const CKM::RawBuffer &encryptedKey);
    void ReleaseObjectHandler(ObjectType type);

    XML::Parser::ElementHandlerPtr GetBufferHandler(EncodingType type);
    void ReleaseBufferHandler(EncodingType type);

    XML::Parser::ElementHandlerPtr GetPermissionHandler();
    void ReleasePermissionHandler();

private:
    class HeaderHandler : public XML::Parser::ElementHandler
    {
    public:
        explicit HeaderHandler(InitialValuesFile & parent);
        virtual void Start(const XML::Parser::Attributes & attr);
        virtual void Characters(const std::string &) {};
        virtual void End() {};

        bool isCorrectVersion() const;

    private:
        int m_version;
        InitialValuesFile & m_parent;
    };

    class EncryptionKeyHandler : public XML::Parser::ElementHandler
    {
    public:
        explicit EncryptionKeyHandler(InitialValuesFile & parent);
        virtual void Start(const XML::Parser::Attributes &) {};
        virtual void Characters(const std::string &data);
        virtual void End();

        CKM::RawBuffer getEncryptedKey() const;
    private:
        CKM::RawBuffer m_encryptedKey;
        InitialValuesFile & m_parent;
    };

    std::string m_filename;
    XML::Parser m_parser;
    InitialValueHandler::InitialValueHandlerPtr m_currentHandler;
    CKMLogic & m_db_logic;
    typedef std::shared_ptr<HeaderHandler> HeaderHandlerPtr;
    typedef std::shared_ptr<EncryptionKeyHandler> EncryptionKeyHandlerPtr;
    HeaderHandlerPtr m_header;
    EncryptionKeyHandlerPtr m_encryptionKeyHandler;
    CKM::RawBuffer m_encryptedAESkey;

    void registerElementListeners();
    static void Error(const XML::Parser::ErrorType errorType,
                      const std::string & logMsg);

};

}
}
#endif /* INITIALVALUESFILE_H_ */
