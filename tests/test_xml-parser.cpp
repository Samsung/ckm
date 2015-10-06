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
 * @file        test_xml-parser.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       XML parser tests.
 */

#include <vector>
#include <boost/test/unit_test.hpp>
#include <parser.h>

using namespace CKM;
using namespace XML;

namespace
{
const char *XML_1_okay          = "XML_1_okay.xml";
const char *XSD_1_okay          = "XML_1_okay.xsd";
const char *XML_1_wrong         = "XML_1_wrong.xml";
const char *XSD_1_wrong         = "XML_1_wrong.xsd";
const char *XML_2_structure     = "XML_2_structure.xml";
const char *XML_3_structure     = "XML_3_structure.xml";

std::string format_test_path(const char *file)
{
    return std::string("/usr/share/ckm-db-test/") + std::string(file);
}

bool startCallbackFlag = false;
XML::Parser::ElementHandlerPtr dummyStartCallback()
{
    startCallbackFlag = true;
    // return empty pointer
    return XML::Parser::ElementHandlerPtr();
}
bool endCallbackFlag = false;
void dummyEndCallback(const XML::Parser::ElementHandlerPtr &)
{
    endCallbackFlag = true;
}
}

BOOST_AUTO_TEST_SUITE(XML_PARSER_TEST)

BOOST_AUTO_TEST_CASE(XmlParserTest_wrong_argument)
{
    std::string emptyPath;
    XML::Parser parser(emptyPath);
    BOOST_REQUIRE(Parser::ErrorCode::ERROR_INVALID_ARGUMENT == parser.Validate(emptyPath));

    // no listeners
    BOOST_REQUIRE(Parser::ErrorCode::ERROR_INVALID_ARGUMENT == parser.Parse());

    BOOST_REQUIRE(Parser::ErrorCode::PARSE_SUCCESS == parser.RegisterElementCb("Key", dummyStartCallback, dummyEndCallback));
    BOOST_REQUIRE(Parser::ErrorCode::ERROR_XML_PARSE_FAILED == parser.Parse());
}

BOOST_AUTO_TEST_CASE(XmlParserTest_no_XML_file)
{
    XML::Parser parser(format_test_path("i-am-not-here").c_str());
    BOOST_REQUIRE(Parser::ErrorCode::ERROR_XML_VALIDATION_FAILED == parser.Validate(format_test_path(XSD_1_okay).c_str()));
}

BOOST_AUTO_TEST_CASE(XmlParserTest_XML1_correct_verify)
{
    XML::Parser parser(format_test_path(XML_1_okay).c_str());
    BOOST_REQUIRE(0 == parser.Validate(format_test_path(XSD_1_okay).c_str()));
}

BOOST_AUTO_TEST_CASE(XmlParserTest_XML1_wrong_verify)
{
    XML::Parser parser(format_test_path(XML_1_wrong).c_str());
    BOOST_REQUIRE(Parser::ErrorCode::ERROR_XML_VALIDATION_FAILED == parser.Validate(format_test_path(XSD_1_okay).c_str()));
}

BOOST_AUTO_TEST_CASE(XmlParserTest_XML1_wrong_schema)
{
    XML::Parser parser(format_test_path(XML_1_okay).c_str());
    BOOST_REQUIRE(Parser::ErrorCode::ERROR_XSD_PARSE_FAILED == parser.Validate(format_test_path(XSD_1_wrong).c_str()));
}

BOOST_AUTO_TEST_CASE(XmlParserTest_XML1_correct_parse_incorrect_callbacks)
{
    XML::Parser parser(format_test_path(XML_1_okay).c_str());
    BOOST_REQUIRE(0 == parser.Validate(format_test_path(XSD_1_okay).c_str()));

    BOOST_REQUIRE(Parser::ErrorCode::PARSE_SUCCESS == parser.RegisterElementCb("Data", NULL, NULL));
    BOOST_REQUIRE(Parser::ErrorCode::PARSE_SUCCESS == parser.Parse());
}

BOOST_AUTO_TEST_CASE(XmlParserTest_XML1_correct_parse)
{
    XML::Parser parser(format_test_path(XML_1_okay).c_str());
    BOOST_REQUIRE(0 == parser.Validate(format_test_path(XSD_1_okay).c_str()));

    BOOST_REQUIRE(Parser::ErrorCode::PARSE_SUCCESS == parser.RegisterElementCb("Key", dummyStartCallback, NULL));
    BOOST_REQUIRE(Parser::ErrorCode::PARSE_SUCCESS == parser.RegisterElementCb("Cert", NULL, dummyEndCallback));
    startCallbackFlag = false;
    endCallbackFlag = false;
    BOOST_REQUIRE(Parser::ErrorCode::PARSE_SUCCESS == parser.Parse());
    BOOST_REQUIRE(startCallbackFlag == true);
    BOOST_REQUIRE(endCallbackFlag == true);
}


class StructureTest
{
public:
    class ExpectedSumHandler : public XML::Parser::ElementHandler
    {
        public:
            ExpectedSumHandler() : m_value(0) {}

            virtual void Start(const XML::Parser::Attributes &) {}
            virtual void Characters(const std::string &data) {
                m_value = atoi(data.c_str());
            }
            virtual void End() {}

            int getSum() const {
                return m_value;
            }

        protected:
            int m_value;
    };

    class MathHandler : public XML::Parser::ElementHandler
    {
        public:
            MathHandler() : m_valueSet(false), m_value(0), m_powerFactor(1) {}

            virtual void Start(const XML::Parser::Attributes &attr) {
                const auto & it = attr.find("powerFactor");
                if(it != attr.end())
                    m_powerFactor = atoi(it->second.c_str());
            }
            virtual void Characters(const std::string &data) {
                m_value = pow(atoi(data.c_str()), m_powerFactor);
                m_valueSet = true;
            }
            virtual void End() {}

            virtual int compute(int prevVal) = 0;

        protected:
            bool m_valueSet;
            int m_value;
            int m_powerFactor;
    };
    class AddHandler : public MathHandler
    {
        public:
            virtual int compute(int prevVal) {
                if( !m_valueSet )
                    return prevVal;

                return prevVal + m_value;
            }
    };

    class MultiplyHandler : public MathHandler
    {
        public:
            virtual int compute(int prevVal) {
                if( !m_valueSet )
                    return prevVal;

                return prevVal * m_value;
            }
    };

    class DivHandler : public MathHandler
    {
        public:
            virtual int compute(int prevVal) {
                if( !m_valueSet )
                    return prevVal;

                if(m_value == 0)
                    return prevVal;
                return prevVal / m_value;
            }
    };

    StructureTest(const char *filename) : m_parser(filename), m_sum(0), m_expectedSum(0)
    {
        m_parser.RegisterErrorCb(StructureTest::Error);
        m_parser.RegisterElementCb("Add",
                [this]() -> XML::Parser::ElementHandlerPtr
                {
                    return std::make_shared<AddHandler>();
                },
                [this](const XML::Parser::ElementHandlerPtr & element)
                {
                    // add computation
                    if(element)
                    {
                        MathHandler *mathElement = reinterpret_cast<MathHandler*>(element.get());
                        m_sum = mathElement->compute(m_sum);
                    }
                });
        m_parser.RegisterElementCb("Multiply",
                [this]() -> XML::Parser::ElementHandlerPtr
                {
                    return std::make_shared<MultiplyHandler>();
                },
                [this](const XML::Parser::ElementHandlerPtr &element)
                {
                    // multiply computation
                    if(element)
                    {
                        MathHandler *mathElement = reinterpret_cast<MathHandler*>(element.get());
                        m_sum = mathElement->compute(m_sum);
                    }
                });
        m_parser.RegisterElementCb("Div",
                [this]() -> XML::Parser::ElementHandlerPtr
                {
                    return std::make_shared<DivHandler>();
                },
                [this](const XML::Parser::ElementHandlerPtr &element)
                {
                    // division computation
                    if(element)
                    {
                        MathHandler *mathElement = reinterpret_cast<MathHandler*>(element.get());
                        m_sum = mathElement->compute(m_sum);
                    }
                });
        m_parser.RegisterElementCb("ExpectedSum",
                [this]() -> XML::Parser::ElementHandlerPtr
                {
                    return std::make_shared<ExpectedSumHandler>();
                },
                [this](const XML::Parser::ElementHandlerPtr &element)
                {
                    if(element)
                    {
                        ExpectedSumHandler *sumElement = reinterpret_cast<ExpectedSumHandler*>(element.get());
                        m_expectedSum = sumElement->getSum();
                    }
                });
    }

    static void Error(const Parser::ErrorType /*errorType*/,
                      const std::string & log_msg)
    {
        BOOST_FAIL(log_msg);
    }

    int Parse()
    {
        return m_parser.Parse();
    }

    int getSum() const {
        return m_sum;
    }
    int getExpectedSum() const {
        return m_expectedSum;
    }
private:
    XML::Parser m_parser;
    int m_sum;
    int m_expectedSum;
};

BOOST_AUTO_TEST_CASE(XmlParserTest_XML2_structure)
{
    StructureTest parser(format_test_path(XML_2_structure).c_str());
    BOOST_REQUIRE(0 == parser.Parse());
    BOOST_REQUIRE_MESSAGE(parser.getSum() == parser.getExpectedSum(),
                          "got sum: " << parser.getSum() << " while expected: " << parser.getExpectedSum());
}

BOOST_AUTO_TEST_SUITE_END()
