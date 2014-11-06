#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>
#include <unistd.h>
#include <db-crypto.h>
#include <iostream>
#include <ckm/ckm-type.h>
#include <ckm/ckm-error.h>
#include <errno.h>
#include <test_common.h>
#include <DBFixture.h>

BOOST_GLOBAL_FIXTURE(TestConfig)

using namespace CKM;

namespace
{
const int restricted_local = 1;
const int restricted_global = 0;

const unsigned int c_test_retries = 1000;
const unsigned int c_num_names = 500;
const unsigned int c_num_names_add_test = 5000;
const unsigned int c_names_per_label = 15;
}


BOOST_FIXTURE_TEST_SUITE(DBCRYPTO_TEST, DBFixture)
BOOST_AUTO_TEST_CASE(DBtestSimple) {
    DBRow rowPattern = create_default_row();
    rowPattern.data = RawBuffer(32, 1);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    check_DB_integrity(rowPattern);
}
BOOST_AUTO_TEST_CASE(DBtestBIG) {
    DBRow rowPattern = create_default_row();
    rowPattern.data = createBigBlob(4096);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    check_DB_integrity(rowPattern);
}
BOOST_AUTO_TEST_CASE(DBtestGlobal) {
    DBRow rowPattern = create_default_row();
    rowPattern.data = RawBuffer(1024, 2);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    BOOST_REQUIRE_NO_THROW(m_db.saveDBRow(rowPattern));

    DBRow name_duplicate = rowPattern;
    rowPattern.ownerLabel = rowPattern.ownerLabel + "1";
}
BOOST_AUTO_TEST_CASE(DBtestTransaction) {
    DBRow rowPattern = create_default_row();
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);
    DBCrypto::Transaction transaction(&m_db);

    BOOST_REQUIRE_NO_THROW(m_db.saveDBRow(rowPattern));
    BOOST_REQUIRE_NO_THROW(transaction.rollback());

    DBCrypto::DBRowOptional row_optional;
    BOOST_REQUIRE_NO_THROW(row_optional = m_db.getDBRow(m_default_name, m_default_label,
                                                        DBDataType::BINARY_DATA));
    BOOST_CHECK_MESSAGE(!row_optional, "Row still present after rollback");
}

BOOST_AUTO_TEST_SUITE_END()



BOOST_FIXTURE_TEST_SUITE(DBCRYPTO_PERF_TEST, DBFixture)

BOOST_AUTO_TEST_CASE(DBperfAddNames)
{
    // actual test
    performance_start("saveDBRow");
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
    performance_start("getDBRow");
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
    performance_start("getDBRow");
    for(unsigned int t=0; t<c_test_retries; t++)
    {
        int name_idx = rand()%c_num_names;
        generate_name(name_idx, name);
        generate_label(name_idx/c_names_per_label, owner_label);
        generate_label(rand()%num_labels, smack_label);

        // do not care of result
        m_db.getDBRow(name, owner_label, DBDataType::BINARY_DATA);
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
    performance_start("deleteDBRow");
    Name name;
    Label label;
    for(unsigned int t=0; t<c_num_names; t++)
    {
        generate_name(t, name);
        generate_label(t/c_names_per_label, label);

        BOOST_REQUIRE_NO_THROW(m_db.deleteDBRow(name, label));
    }
    performance_stop(c_num_names);

    // verify everything has been removed
    unsigned int num_labels = c_num_names / c_names_per_label;
    for(unsigned int l=0; l<num_labels; l++)
    {
        generate_label(l, label);
        LabelNameVector expect_no_data;
        BOOST_REQUIRE_NO_THROW(m_db.listNames(label, expect_no_data, DBDataType::BINARY_DATA));
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

        BOOST_REQUIRE_NO_THROW(m_db.listNames(label, ret_list, DBDataType::BINARY_DATA));
        BOOST_REQUIRE(c_num_names == ret_list.size());
        ret_list.clear();
    }
    performance_stop(c_test_retries/num_labels);
}

BOOST_AUTO_TEST_SUITE_END()
