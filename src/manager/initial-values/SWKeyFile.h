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
 * @file        SWKeyFile.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       SWKeyFile class.
 */

#ifndef SWKEYFILE_H_
#define SWKEYFILE_H_

#include <parser.h>
#include <InitialValueHandler.h>
#include <ckm-logic.h>
#include <string>
#include <algorithm>
#include <cctype>
#include <xml-utils.h>
#include <base64.h>
#include <generic-backend/gobj.h>
#include <dpl/log/log.h>
namespace CKM {
namespace InitialValues {


class SWKeyFile {
public:
    explicit SWKeyFile(const std::string &XML_filename);

    int Validate(const std::string &XSD_file);
    int Parse();

    Crypto::GObjShPtr getPrivKey()
    {
        return m_deviceKey;
    }

private:
    class HeaderHandler : public XML::Parser::ElementHandler {
    public:
        explicit HeaderHandler(SWKeyFile & parent);
        virtual void Start(const XML::Parser::Attributes & attr);
        virtual void Characters(const std::string &) {}
        virtual void End() {}

        bool isCorrectVersion() const;

    private:
        int m_version;
        SWKeyFile & m_parent;
    };

    class RSAKeyHandler : public XML::Parser::ElementHandler {
    public:
        explicit RSAKeyHandler(SWKeyFile & parent);
        virtual void Start(const XML::Parser::Attributes &) {}
        virtual void Characters(const std::string &data);
        virtual void End();

        Crypto::GObjShPtr getPrivKey();

    private:
        CKM::RawBuffer m_encryptedKey;
        SWKeyFile & m_parent;
    };

    std::string m_filename;
    XML::Parser m_parser;
    typedef std::shared_ptr<HeaderHandler> HeaderHandlerPtr;
    typedef std::shared_ptr<RSAKeyHandler> RSAKeyHandlerPtr;
    HeaderHandlerPtr m_header;
    RSAKeyHandlerPtr m_RSAKeyHandler;
    Crypto::GObjShPtr m_deviceKey;

    void registerElementListeners();
    static void Error(const XML::Parser::ErrorType errorType,
                      const std::string & logMsg);
};

}
}
#endif /* SWKEYFILE_H_ */
