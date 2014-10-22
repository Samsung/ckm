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
const unsigned int c_num_aliases = 500;
const unsigned int c_num_aliases_add_test = 5000;
const unsigned int c_alias_per_label = 15;
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

    DBRow alias_duplicate = rowPattern;
    rowPattern.smackLabel = rowPattern.smackLabel + "1";

    BOOST_REQUIRE_THROW(m_db.saveDBRow(alias_duplicate),
            DBCrypto::Exception::AliasExists);
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
    BOOST_REQUIRE_NO_THROW(row_optional = m_db.getDBRow(m_default_alias, m_default_label,
            DBDataType::BINARY_DATA));
    BOOST_CHECK_MESSAGE(!row_optional, "Row still present after rollback");

}

BOOST_AUTO_TEST_CASE(DBaddDataCheckIfPermissionIsAdded)
{
    std::string row_A_alias, row_B_alias;
    std::string row_A_label, row_B_label;
    generate_alias(0, row_A_alias); generate_label(0, row_A_label);
    generate_alias(1, row_B_alias); generate_label(1, row_B_label);

    // insert initial data set
    insert_row(row_A_alias, row_A_label);
    insert_row(row_B_alias, row_B_label);
    read_row_expect_success(row_A_alias, row_A_label);
    read_row_expect_success(row_B_alias, row_B_label);

    // verify that no entries present in the permission table
    // read row A from label B and vice versa
    read_row_expect_fail(row_A_alias, row_B_label);
    read_row_expect_fail(row_B_alias, row_A_label);

    // add appropriate permissions for label B
    add_permission(row_A_alias, row_A_label, row_B_label);

    // B should have access to A, while A should not to B
    // read row A from label B and vice versa
    read_row_expect_success(row_A_alias, row_B_label);
    read_row_expect_fail(row_B_alias, row_A_label);

    // add appropriate permissions for label A
    add_permission(row_B_alias, row_B_label, row_A_label);

    // B should have access to A, same as A have access to B
    // read row A from label B and vice versa
    read_row_expect_success(row_A_alias, row_B_label);
    read_row_expect_success(row_B_alias, row_A_label);
}


BOOST_AUTO_TEST_CASE(DBremoveDataCheckIfPermissionIsRemoved)
{
    std::string row_A_alias, row_B_alias, row_C_alias;
    std::string row_A_label, row_B_label, row_C_label;
    generate_alias(0, row_A_alias); generate_label(0, row_A_label);
    generate_alias(1, row_B_alias); generate_label(1, row_B_label);
    generate_alias(2, row_C_alias); generate_label(2, row_C_label);

    // insert initial data set
    insert_row(row_A_alias, row_A_label);
    insert_row(row_B_alias, row_B_label);
    insert_row(row_C_alias, row_C_label);
    add_permission(row_A_alias, row_A_label, row_B_label);
    add_permission(row_B_alias, row_B_label, row_A_label);
    // to test multiple permissions removal
    // put intentionally after row_B_alias permission entry
    add_permission(row_A_alias, row_A_label, row_C_label);

    // B should have access to A, same as A have access to B
    // read row A from label B and vice versa
    read_row_expect_success(row_A_alias, row_B_label);
    read_row_expect_success(row_A_alias, row_C_label);
    read_row_expect_success(row_B_alias, row_A_label);
    read_row_expect_fail(row_B_alias, row_C_label);

    // remove data A - expect permissions for B and C to be removed as well
    delete_row(row_A_alias, row_A_label);
    // insert it again - expect permissions for label B and C not to be there anymore
    insert_row(row_A_alias, row_A_label);

    // read row A from label B and vice versa
    read_row_expect_fail(row_A_alias, row_B_label);
    read_row_expect_fail(row_A_alias, row_C_label);
    read_row_expect_success(row_B_alias, row_A_label);

    // remove data B - expect permission to be removed as well
    delete_row(row_B_alias, row_B_label);
    // insert it again - expect permissions for label A not to be there anymore
    insert_row(row_B_alias, row_B_label);

    // read row A from label B and vice versa
    read_row_expect_fail(row_A_alias, row_B_label);
    read_row_expect_fail(row_A_alias, row_C_label);
    read_row_expect_fail(row_B_alias, row_A_label);

    // sanity check: data exists
    read_row_expect_success(row_A_alias, row_A_label);
    read_row_expect_success(row_B_alias, row_B_label);
}
BOOST_AUTO_TEST_SUITE_END()



BOOST_FIXTURE_TEST_SUITE(DBCRYPTO_PERF_TEST, DBFixture)

BOOST_AUTO_TEST_CASE(DBperfAddAliases)
{
    // actual test
    performance_start("saveDBRow");
    {
        generate_perf_DB(c_num_aliases_add_test, c_alias_per_label);
    }
    performance_stop(c_num_aliases_add_test);
}

BOOST_AUTO_TEST_CASE(DBperfLookupAliasByOwner)
{
    // prepare data
    generate_perf_DB(c_num_aliases, c_alias_per_label);

    unsigned int num_labels = c_num_aliases/c_alias_per_label;
    std::string alias, label;

    // actual test - successful lookup
    performance_start("getDBRow");
    for(unsigned int t=0; t<c_test_retries; t++)
    {
        int label_num = rand() % num_labels;
        generate_label(label_num, label);

        unsigned int start_alias = label_num*c_alias_per_label;
        for(unsigned int alias_num=start_alias; alias_num<(start_alias+c_alias_per_label); alias_num++)
        {
            generate_alias(alias_num, alias);
            read_row_expect_success(alias, label);
        }
    }
    performance_stop(c_test_retries * c_num_aliases);
}

BOOST_AUTO_TEST_CASE(DBperfLookupAliasByNotAllowed)
{
    // prepare data
    generate_perf_DB(c_num_aliases, c_alias_per_label);

    std::string alias, label;
    const unsigned int unavailable_label_idx = (c_num_aliases/c_alias_per_label) + 1;
    generate_label(unavailable_label_idx, label);

    // actual test - failure lookup
    performance_start("getDBRow");
    for(unsigned int t=0; t<c_test_retries; t++)
    {
        generate_alias(rand()%c_num_aliases, alias);

        read_row_expect_fail(alias, label);
    }
    performance_stop(c_test_retries * c_num_aliases);
}

BOOST_AUTO_TEST_CASE(DBperfLookupAliasRandomOwnershipNoPermissions)
{
    // prepare data
    generate_perf_DB(c_num_aliases, c_alias_per_label);

    std::string alias, label;
    unsigned int num_labels = c_num_aliases / c_alias_per_label;

    // actual test - random lookup
    performance_start("getDBRow");
    for(unsigned int t=0; t<c_test_retries; t++)
    {
        generate_alias(rand()%c_num_aliases, alias);
        generate_label(rand()%num_labels, label);

        try
        {
            m_db.getDBRow(alias, label, DBDataType::BINARY_DATA);
        }
        catch (const DBCrypto::Exception::PermissionDenied &e) {}
    }
    performance_stop(c_test_retries * c_num_aliases);
}

BOOST_AUTO_TEST_CASE(DBperfAddPermissions)
{
    // prepare data
    generate_perf_DB(c_num_aliases, c_alias_per_label);

    // actual test - add access rights
    performance_start("setAccessRights");
    long iterations = add_full_access_rights(c_num_aliases, c_alias_per_label);
    performance_stop(iterations);
}

BOOST_AUTO_TEST_CASE(DBperfLookupAliasRandomOwnershipWithPermissions)
{
    // prepare data
    generate_perf_DB(c_num_aliases, c_alias_per_label);
    add_full_access_rights(c_num_aliases, c_alias_per_label);

    std::string alias, label;
    unsigned int num_labels = c_num_aliases / c_alias_per_label;

    // actual test - random lookup
    performance_start("getDBRow/perm");
    for(unsigned int t=0; t<c_test_retries; t++)
    {
        generate_alias(rand()%c_num_aliases, alias);
        generate_label(rand()%num_labels, label);

        read_row_expect_success(alias, label);
    }
    performance_stop(c_test_retries * c_num_aliases);
}

BOOST_AUTO_TEST_CASE(DBperfAliasRemoval)
{
    // prepare data
    generate_perf_DB(c_num_aliases, c_alias_per_label);
    add_full_access_rights(c_num_aliases, c_alias_per_label);

    // actual test - random lookup
    performance_start("deleteDBRow");
    std::string alias, label;
    for(unsigned int t=0; t<c_num_aliases; t++)
    {
        generate_alias(t, alias);
        generate_label(t/c_alias_per_label, label);

        BOOST_REQUIRE_NO_THROW(m_db.deleteDBRow(alias, label));
    }
    performance_stop(c_num_aliases);

    // verify everything has been removed
    unsigned int num_labels = c_num_aliases / c_alias_per_label;
    for(unsigned int l=0; l<num_labels; l++)
    {
        generate_label(l, label);
        LabelAliasVector expect_no_data;
        BOOST_REQUIRE_NO_THROW(m_db.getAliases(label, DBDataType::BINARY_DATA, expect_no_data));
        BOOST_REQUIRE(0 == expect_no_data.size());
    }
}

BOOST_AUTO_TEST_CASE(DBperfGetAliasList)
{
    // prepare data
    generate_perf_DB(c_num_aliases, c_alias_per_label);
    add_full_access_rights(c_num_aliases, c_alias_per_label);

    unsigned int num_labels = c_num_aliases / c_alias_per_label;
    std::string label;

    // actual test - random lookup
    performance_start("getAliases");
    for(unsigned int t=0; t<(c_test_retries/num_labels); t++)
    {
        LabelAliasVector ret_list;
        generate_label(rand()%num_labels, label);

        BOOST_REQUIRE_NO_THROW(m_db.getAliases(label, DBDataType::BINARY_DATA, ret_list));
        BOOST_REQUIRE(c_num_aliases == ret_list.size());
        ret_list.clear();
    }
    performance_stop(c_test_retries/num_labels);
}

BOOST_AUTO_TEST_SUITE_END()
