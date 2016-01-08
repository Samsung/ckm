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
 * @file        test_db_crypto.cpp
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version
 * @brief
 */
#include <boost/test/unit_test.hpp>
#include <unistd.h>
#include <db-crypto.h>
#include <iostream>
#include <ckm/ckm-type.h>
#include <ckm/ckm-error.h>
#include <errno.h>
#include <test_common.h>
#include <DBFixture.h>

using namespace CKM;

namespace
{
const int restricted_local = 1;
const int restricted_global = 0;

const unsigned int c_test_retries = 1000;
const unsigned int c_num_names = 500;
const unsigned int c_num_names_add_test = 5000;
const unsigned int c_names_per_label = 15;

} // namespace anonymous

BOOST_FIXTURE_TEST_SUITE(DBCRYPTO_TEST, DBFixture)
BOOST_AUTO_TEST_CASE(DBtestSimple) {
    DB::Row rowPattern = create_default_row();
    rowPattern.data = RawBuffer(32, 1);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    check_DB_integrity(rowPattern);
}
BOOST_AUTO_TEST_CASE(DBtestBIG) {
    DB::Row rowPattern = create_default_row();
    rowPattern.data = createBigBlob(4096);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    check_DB_integrity(rowPattern);
}
BOOST_AUTO_TEST_CASE(DBtestGlobal) {
    DB::Row rowPattern = create_default_row();
    rowPattern.data = RawBuffer(1024, 2);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    BOOST_REQUIRE_NO_THROW(m_db.saveRow(rowPattern));

    DB::Row name_duplicate = rowPattern;
    rowPattern.ownerLabel = rowPattern.ownerLabel + "1";
}
BOOST_AUTO_TEST_CASE(DBtestTransaction) {
    DB::Row rowPattern = create_default_row();
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);
    DB::Crypto::Transaction transaction(&m_db);

    BOOST_REQUIRE_NO_THROW(m_db.saveRow(rowPattern));
    BOOST_REQUIRE_NO_THROW(transaction.rollback());

    DB::Crypto::RowOptional row_optional;
    BOOST_REQUIRE_NO_THROW(row_optional = m_db.getRow(m_default_name, m_default_label,
                                                      DataType::BINARY_DATA));
    BOOST_CHECK_MESSAGE(!row_optional, "Row still present after rollback");
}

BOOST_AUTO_TEST_CASE(DBtestBackend) {
    DB::Row rowPattern = create_default_row();
    rowPattern.data = RawBuffer(32, 1);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    rowPattern.backendId =  CryptoBackend::OpenSSL;
    check_DB_integrity(rowPattern);

    rowPattern.backendId =  CryptoBackend::TrustZone;
    check_DB_integrity(rowPattern);

    rowPattern.backendId =  CryptoBackend::None;
    check_DB_integrity(rowPattern);
}

BOOST_AUTO_TEST_SUITE_END()



BOOST_FIXTURE_TEST_SUITE(DBCRYPTO_PERF_TEST, DBFixture)

BOOST_AUTO_TEST_CASE(DBperfAddNames)
{
    // actual test
    performance_start("saveRow");
    {
        generate_perf_DB(c_num_names_add_test, c_names_per_label);
    }
    performance_stop(c_num_names_add_test);
}

BOOST_AUTO_TEST_CASE(DBperfLookupAliasByOwner)
{
    // prepare data
    generate_perf_DB(c_num_names, c_names_per_label);

    unsigned int num_labels = c_num_names/c_names_per_label;
    Name name;
    Label label;

    // actual test - successful lookup
    performance_start("getRow");
    for(unsigned int t=0; t<c_test_retries; t++)
    {
        int label_num = rand() % num_labels;
        generate_label(label_num, label);

        unsigned int start_name = label_num*c_names_per_label;
        for(unsigned int name_num=start_name; name_num<(start_name+c_names_per_label); name_num++)
        {
            generate_name(name_num, name);
            read_row_expect_success(name, label);
        }
    }
    performance_stop(c_test_retries * c_num_names);
}

BOOST_AUTO_TEST_CASE(DBperfLookupAliasRandomOwnershipNoPermissions)
{
    // prepare data
    generate_perf_DB(c_num_names, c_names_per_label);

    Name name;
    Label owner_label;
    Label smack_label;
    unsigned int num_labels = c_num_names / c_names_per_label;

    // actual test - random lookup
    performance_start("getRow");
    for(unsigned int t=0; t<c_test_retries; t++)
    {
        int name_idx = rand()%c_num_names;
        generate_name(name_idx, name);
        generate_label(name_idx/c_names_per_label, owner_label);
        generate_label(rand()%num_labels, smack_label);

        // do not care of result
        m_db.getRow(name, owner_label, DataType::BINARY_DATA);
    }
    performance_stop(c_test_retries * c_num_names);
}

BOOST_AUTO_TEST_CASE(DBperfAddPermissions)
{
    // prepare data
    generate_perf_DB(c_num_names, c_names_per_label);

    // actual test - add access rights
    performance_start("setPermission");
    long iterations = add_full_access_rights(c_num_names, c_names_per_label);
    performance_stop(iterations);
}

BOOST_AUTO_TEST_CASE(DBperfAliasRemoval)
{
    // prepare data
    generate_perf_DB(c_num_names, c_names_per_label);
    add_full_access_rights(c_num_names, c_names_per_label);

    // actual test - random lookup
    performance_start("deleteRow");
    Name name;
    Label label;
    for(unsigned int t=0; t<c_num_names; t++)
    {
        generate_name(t, name);
        generate_label(t/c_names_per_label, label);

        BOOST_REQUIRE_NO_THROW(m_db.deleteRow(name, label));
    }
    performance_stop(c_num_names);

    // verify everything has been removed
    unsigned int num_labels = c_num_names / c_names_per_label;
    for(unsigned int l=0; l<num_labels; l++)
    {
        generate_label(l, label);
        LabelNameVector expect_no_data;
        BOOST_REQUIRE_NO_THROW(m_db.listNames(label, expect_no_data, DataType::BINARY_DATA));
        BOOST_REQUIRE(0 == expect_no_data.size());
    }
}

BOOST_AUTO_TEST_CASE(DBperfGetAliasList)
{
    // prepare data
    generate_perf_DB(c_num_names, c_names_per_label);
    add_full_access_rights(c_num_names, c_names_per_label);

    unsigned int num_labels = c_num_names / c_names_per_label;
    Label label;

    // actual test - random lookup
    performance_start("listNames");
    for(unsigned int t=0; t<(c_test_retries/num_labels); t++)
    {
        LabelNameVector ret_list;
        generate_label(rand()%num_labels, label);

        BOOST_REQUIRE_NO_THROW(m_db.listNames(label, ret_list, DataType::BINARY_DATA));
        BOOST_REQUIRE(c_num_names == ret_list.size());
        ret_list.clear();
    }
    performance_stop(c_test_retries/num_labels);
}
BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(DBCRYPTO_MIGRATION_TEST)
namespace
{
const unsigned migration_names = 16107;
const unsigned migration_labels = 273;
const unsigned migration_reference_label_idx = 0;
const unsigned migration_accessed_element_idx = 7;

void verifyDBisValid(DBFixture & fixture)
{
    /**
     * there are (migration_labels), each having (migration_names)/(migration_labels) entries.
     * reference label (migration_reference_label_idx) exists such that it has access to
     * all others' label element with index (migration_accessed_element_idx).
     *
     * Example:
     * - migration_label_63 has access to all items owned by migration_label_63,
     *   which gives (migration_names)/(migration_labels) entries.
     *
     * - migration_label_0 (0 is the reference label) has access to all items
     *   owned by migration_label_0 and all others' label element index 7,
     *   which gives (migration_names)/(migration_labels)  + (migration_labels-1) entries.
     *
     */
    Label reference_label;
    fixture.generate_label(migration_reference_label_idx, reference_label);

    // check number of elements accessible to the reference label
    LabelNameVector ret_list;
    BOOST_REQUIRE_NO_THROW(fixture.m_db.listNames(reference_label, ret_list, DataType::BINARY_DATA));
    BOOST_REQUIRE((migration_names/migration_labels)/*own items*/ + (migration_labels-1)/*other labels'*/ == ret_list.size());
    ret_list.clear();

    // check number of elements accessible to the other labels
    for(unsigned int l=0; l<migration_labels; l++)
    {
        // bypass the reference owner label
        if(l == migration_reference_label_idx)
            continue;

        Label current_label;
        fixture.generate_label(l, current_label);
        BOOST_REQUIRE_NO_THROW(fixture.m_db.listNames(current_label, ret_list, DataType::BINARY_DATA));
        BOOST_REQUIRE((migration_names/migration_labels) == ret_list.size());
        for(auto it: ret_list)
            BOOST_REQUIRE(it.first == current_label);
        ret_list.clear();
    }
}

struct DBVer1Migration : public DBFixture
{
    DBVer1Migration() : DBFixture(DB_TEST_DIR "/testme_ver1.db")
    {}
};

struct DBVer2Migration : public DBFixture
{
    DBVer2Migration() : DBFixture(DB_TEST_DIR "/testme_ver2.db")
    {}
};

struct DBVer3Migration : public DBFixture
{
    DBVer3Migration() : DBFixture(DB_TEST_DIR "/testme_ver3.db")
    {}
};
}

BOOST_AUTO_TEST_CASE(DBMigrationDBVer1)
{
    DBVer1Migration DBver1;
    verifyDBisValid(DBver1);
}

BOOST_AUTO_TEST_CASE(DBMigrationDBVer2)
{
    DBVer2Migration DBver2;
    verifyDBisValid(DBver2);
}

BOOST_AUTO_TEST_CASE(DBMigrationDBVer3)
{
    DBVer3Migration DBver3;
    verifyDBisValid(DBver3);
}

BOOST_AUTO_TEST_CASE(DBMigrationDBCurrent)
{
    DBFixture currentDB;

    // prepare data using current DB mechanism
    Label reference_label;
    currentDB.generate_label(migration_reference_label_idx, reference_label);
    {
        currentDB.generate_perf_DB(migration_names, migration_names/migration_labels);

        // only the reference label has access to the other labels element <migration_accessed_element_idx>
        for(unsigned int l=0; l<migration_labels; l++)
        {
            // bypass the reference owner label
            if(l == migration_reference_label_idx)
                continue;

            unsigned element_index = migration_accessed_element_idx + l*migration_names/migration_labels;

            // add permission
            Name accessed_name;
            currentDB.generate_name(element_index, accessed_name);
            Label current_label;
            currentDB.generate_label(l, current_label);
            currentDB.add_permission(accessed_name, current_label, reference_label);
        }
    }

    verifyDBisValid(currentDB);
}

BOOST_AUTO_TEST_SUITE_END()
