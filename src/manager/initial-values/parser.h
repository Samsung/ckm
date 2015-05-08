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
 * @file        parser.h
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       XML parser class.
 */

#ifndef XML_PARSER_H_
#define XML_PARSER_H_

#include <map>
#include <vector>
#include <string>
#include <stack>
#include <functional>
#include <memory>
#include <libxml/parser.h>
#include <libxml/tree.h>

namespace CKM {
namespace XML {

class Parser
{
public:
    enum ErrorCode {
        PARSE_SUCCESS                  =   0,
        ERROR_UNKNOWN                  =   -1000,
        ERROR_XML_VALIDATION_FAILED    =   -1001,
        ERROR_XSD_PARSE_FAILED         =   -1002,
        ERROR_XML_PARSE_FAILED         =   -1003,
        ERROR_INVALID_ARGUMENT         =   -1004,
        ERROR_CALLBACK_PRESENT         =   -1005,
        ERROR_INVALID_VERSION          =   -1006,
        ERROR_INTERNAL                 =   -1007,
        ERROR_NO_MEMORY                =   -1008
    };

    explicit Parser(const std::string &XML_filename);
    virtual ~Parser();

    int Validate(const std::string &XSD_schema);
    int Parse();

    enum ErrorType {
        VALIDATION_ERROR,
        PARSE_ERROR,
        PARSE_WARNING
    };
    typedef std::function<void (const ErrorType, const std::string &)> ErrorCb;
    int RegisterErrorCb(const ErrorCb newCb);

    typedef std::map<std::string, std::string> Attributes;
    class ElementHandler
    {
        public:
            virtual ~ElementHandler() {}

            // methods below may throw std::exception to invalidate the parsing process
            // and remove all element listeners.
            // In this case, parsing error code returned to the user after std::exception.
            virtual void Start(const Attributes &) = 0;
            virtual void Characters(const std::string & data) = 0;
            virtual void End() = 0;
    };
    typedef std::shared_ptr<ElementHandler> ElementHandlerPtr;

    typedef std::function<ElementHandlerPtr ()> StartCb;
    typedef std::function<void (const ElementHandlerPtr &)> EndCb;
    int RegisterElementCb(const char * elementName,
                          const StartCb startCb,
                          const EndCb endCb);

protected:
    void StartElement(const xmlChar *name,
                      const xmlChar **attrs);
    void EndElement(const xmlChar *name);
    void Characters(const xmlChar *ch, size_t chLen);
    void Error(const ErrorType errorType, const char *msg, va_list &);

private:
    static void StartElement(void *userData,
                             const xmlChar *name,
                             const xmlChar **attrs);
    static void EndElement(void *userData,
                           const xmlChar *name);
    static void Characters(void *userData,
                           const xmlChar *ch,
                           int len);
    static void ErrorValidate(void *userData,
                              const char *msg,
                              ...);
    static void Error(void *userData,
                      const char *msg,
                      ...);
    static void Warning(void *userData,
                        const char *msg,
                        ...);

private:
    xmlSAXHandler           m_saxHandler;
    std::string             m_XMLfile;
    ErrorCb                 m_errorCb;

    struct ElementListener
    {
        StartCb     startCb;
        EndCb       endCb;
    };
    std::map<std::string, ElementListener> m_elementListenerMap;
    std::stack<ElementHandlerPtr> m_elementHandlerStack;

    void CallbackHelper(std::function<void (void)> func);
};

}
}
#endif /* XML_PARSER_H_ */
