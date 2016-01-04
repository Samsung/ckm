/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Kyungwook Tak <k.tak@samsung.com>
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
 * @file        test_sql.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version
 * @brief
 */
#include <dpl/db/sql_connection.h>
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <assert.h>
#include <sqlcipher.h>
#include <ckm/ckm-type.h>
#include <errno.h>

#include <test_common.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wdeprecated-declarations"


const char *encrypt_me = "/tmp/encryptme.db";
const char *encrypt_me_not = "/tmp/encryptmenot.db";

const char *create_table = "CREATE TABLE t1(a,b);";
const char *insert_table = "INSERT INTO t1(a,b) VALUES ("
                                       " 'one for the money',"
                                       " 'two for the show');";
const char *select_table = "SELECT * FROM t1";

CKM::RawBuffer raw_password = createDefaultPass();

BOOST_AUTO_TEST_SUITE(SQL_TEST)
BOOST_AUTO_TEST_CASE(sqlTestConversion){

    BOOST_REQUIRE_MESSAGE(raw_password.size() == RAW_PASS_SIZE,
            "Password should have 32 characters, got: " << raw_password.size());
    std::string pass_check = rawToHexString(raw_password);
    BOOST_REQUIRE_MESSAGE(pass_check.length() == HEX_PASS_SIZE,
            "Hex string should have 64 characters, got: " << pass_check.length());
    BOOST_CHECK(pass_check == pattern);
}

BOOST_AUTO_TEST_CASE(sqlTestSetKeyTooShort) {
    using namespace CKM::DB;
    BOOST_CHECK(unlink(encrypt_me_not) == 0 || errno == ENOENT);
    SqlConnection connection(encrypt_me_not,
                               SqlConnection::Flag::CRW);
    CKM::RawBuffer wrong_key(RAW_PASS_SIZE - 1, 1);
    BOOST_REQUIRE_THROW(connection.SetKey(wrong_key),
            SqlConnection::Exception::InvalidArguments);
}

BOOST_AUTO_TEST_CASE(sqlTestSetKeyTooLong) {
    using namespace CKM::DB;
    BOOST_CHECK(unlink(encrypt_me_not) == 0 || errno == ENOENT);
    SqlConnection connection(encrypt_me_not,
                               SqlConnection::Flag::CRW);
    CKM::RawBuffer wrong_key(RAW_PASS_SIZE + 1, 1);
    BOOST_REQUIRE_THROW(connection.SetKey(wrong_key),
            SqlConnection::Exception::InvalidArguments);
}

BOOST_AUTO_TEST_CASE(sqlTestConnectionUnencrypted) {
    using namespace CKM::DB;
    BOOST_CHECK(unlink(encrypt_me_not) == 0 || errno == ENOENT);
    {
        SqlConnection encrypting_you_not(encrypt_me_not,
                                     SqlConnection::Flag::CRW);
        BOOST_REQUIRE_NO_THROW(encrypting_you_not.ExecCommand(create_table));
        BOOST_REQUIRE_NO_THROW(encrypting_you_not.ExecCommand(insert_table));
    }
    {
        SqlConnection encrypting_you_not(encrypt_me_not,
                                     SqlConnection::Flag::RW);
        SqlConnection::DataCommandUniquePtr selectCommand;
        BOOST_REQUIRE_NO_THROW(selectCommand = encrypting_you_not.
            PrepareDataCommand(select_table));
        BOOST_REQUIRE_NO_THROW(selectCommand->Step());
        std::string value;
        BOOST_REQUIRE_NO_THROW(value = selectCommand->GetColumnString(0));
        BOOST_REQUIRE(value == "one for the money");
    }
}

BOOST_AUTO_TEST_CASE(sqlTestConnectionEncrypted) {
    using namespace CKM::DB;
    BOOST_CHECK(unlink(encrypt_me) == 0 || errno == ENOENT);
    {
        SqlConnection encrypting_you(encrypt_me,
                                     SqlConnection::Flag::CRW);
        BOOST_REQUIRE_NO_THROW(encrypting_you.SetKey(raw_password));
        BOOST_REQUIRE_NO_THROW(encrypting_you.ExecCommand(create_table));
        BOOST_REQUIRE_NO_THROW(encrypting_you.ExecCommand(insert_table));
    }
    {
        SqlConnection encrypting_you(encrypt_me,
                                     SqlConnection::Flag::RW);
        encrypting_you.SetKey(raw_password);
        SqlConnection::DataCommandUniquePtr selectCommand;
        BOOST_REQUIRE_NO_THROW(selectCommand = encrypting_you.
            PrepareDataCommand(select_table));
        BOOST_REQUIRE_NO_THROW(selectCommand->Step());
        std::string value;
        BOOST_REQUIRE_NO_THROW(value = selectCommand->GetColumnString(0));
        BOOST_REQUIRE(value == "one for the money");
    }
}

BOOST_AUTO_TEST_CASE(sqlTestConnectionEncryptedNegative) {

    using namespace CKM::DB;
    BOOST_CHECK(unlink(encrypt_me) == 0 || errno == ENOENT);
    {
        SqlConnection encrypting_you(encrypt_me,
                                     SqlConnection::Flag::CRW);
        BOOST_REQUIRE_NO_THROW(encrypting_you.SetKey(raw_password));
        BOOST_REQUIRE_NO_THROW(encrypting_you.ExecCommand(create_table));
        BOOST_REQUIRE_NO_THROW(encrypting_you.ExecCommand(insert_table));
    }
    {
        SqlConnection encrypting_you(encrypt_me,
                                     SqlConnection::Flag::RW);
        CKM::RawBuffer wrong_password;
        for(std::size_t i = 0; i < RAW_PASS_SIZE; i++) {
            wrong_password.push_back(raw_password[i] + 1);
        }
        BOOST_REQUIRE_NO_THROW(encrypting_you.SetKey(wrong_password));

        SqlConnection::DataCommandUniquePtr selectCommand;
        BOOST_REQUIRE_THROW(selectCommand = encrypting_you.PrepareDataCommand(select_table),
                SqlConnection::Exception::SyntaxError)
    }
}
BOOST_AUTO_TEST_SUITE_END()
#pragma GCC diagnostic pop
