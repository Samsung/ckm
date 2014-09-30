#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>
#include <unistd.h>
#include <db-crypto.h>
#include <iostream>
#include <ckm/ckm-type.h>
#include <ckm/ckm-error.h>
#include <errno.h>

#include <test_common.h>

BOOST_GLOBAL_FIXTURE(TestConfig)

using namespace CKM;

namespace
{

const char* default_alias = "alias";
const char* default_label = "label";

const char* crypto_db = "/tmp/testme.db";

const int restricted_local = 1;
const int restricted_global = 0;

// mirrors the API-defined value
#define AES_GCM_TAG_SIZE 16

const char *row_A_alias = "row_A_alias";
const char *row_A_label = "app_A";

const char *row_B_alias = "row_B_alias";
const char *row_B_label = "app_B";

const char *row_C_alias = "row_C_alias";
const char *row_C_label = "app_C";

void initDB(DBCrypto & db)
{
    BOOST_CHECK(unlink(crypto_db) == 0 || errno == ENOENT);
    BOOST_REQUIRE_NO_THROW(db = DBCrypto(crypto_db, defaultPass));
}

DBRow createDefaultRow( DBDataType type = DBDataType::BINARY_DATA,
                        const char *optional_alias = NULL,
                        const char *optional_label = NULL)
{
    DBRow row;
    row.alias = optional_alias?optional_alias:default_alias;
    row.smackLabel = optional_label?optional_label:default_label;
    row.exportable = 1;
    row.algorithmType = DBCMAlgType::AES_GCM_256;
    row.dataType = type;
    row.iv = createDefaultPass();
    row.encryptionScheme = 0;
    row.dataSize = 0;

    return row;
}

void compareDBRow(const DBRow &lhs, const DBRow &rhs) {
    BOOST_CHECK_MESSAGE(lhs.alias == rhs.alias,
            "Aliases didn't match! Got: " << rhs.alias
                << " , expected : " << lhs.alias);

    BOOST_CHECK_MESSAGE(lhs.smackLabel == rhs.smackLabel,
            "smackLabel didn't match! Got: " << rhs.smackLabel
                << " , expected : " << lhs.smackLabel);

    BOOST_CHECK_MESSAGE(lhs.exportable == rhs.exportable,
            "exportable didn't match! Got: " << rhs.exportable
                << " , expected : " << lhs.exportable);

    BOOST_CHECK_MESSAGE(lhs.iv == rhs.iv,
            "iv didn't match! Got: " << rhs.iv.size()
                << " , expected : " << lhs.iv.size());

    BOOST_CHECK_MESSAGE(lhs.data == rhs.data,
            "data didn't match! Got: " << rhs.data.size()
                << " , expected : " << lhs.data.size());
}

void checkDBIntegrity(const DBRow &rowPattern, DBCrypto &db) {

    BOOST_REQUIRE_NO_THROW(db.saveDBRow(rowPattern));
    DBRow selectRow = rowPattern;

    DBCrypto::DBRowOptional optional_row;
    BOOST_REQUIRE_NO_THROW(optional_row = db.getDBRow("alias", "label", DBDataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(optional_row, "Select didn't return any row");

    compareDBRow(selectRow, rowPattern);
    DBRow alias_duplicate = rowPattern;
    alias_duplicate.data = createDefaultPass();
    alias_duplicate.dataSize = alias_duplicate.data.size();

    BOOST_REQUIRE_THROW(db.saveDBRow(alias_duplicate), DBCrypto::Exception::AliasExists);
    unsigned int erased;
    BOOST_REQUIRE_NO_THROW(erased = db.deleteDBRow("alias", "label"));
    BOOST_REQUIRE_MESSAGE(erased > 0, "Inserted row didn't exist in db");

    DBCrypto::DBRowOptional row_optional;
    BOOST_REQUIRE_NO_THROW(row_optional = db.getDBRow("alias", "label", DBDataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(!row_optional, "Select should not return row after deletion");
}

void insertRow(DBCrypto & db, const char *alias, const char *label)
{
    DBRow rowPattern = createDefaultRow(DBDataType::BINARY_DATA, alias, label);
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);
    BOOST_REQUIRE_NO_THROW(db.saveDBRow(rowPattern));
}

void deleteRow(DBCrypto & db, const char *alias, const char *label)
{
    bool exit_flag;
    BOOST_REQUIRE_NO_THROW(exit_flag = db.deleteDBRow(alias, label));
    BOOST_REQUIRE_MESSAGE(true == exit_flag, "remove alias failed: no rows removed");
}

void addPermission(DBCrypto & db, const char *alias, const char *owner_label, const char *accessor_label)
{
    int ec;
    BOOST_REQUIRE_NO_THROW(ec = db.setAccessRights(std::string(owner_label),
                                                   std::string(alias),
                                                   std::string(accessor_label),
                                                   CKM::AccessRight::AR_READ_REMOVE));
    BOOST_REQUIRE_MESSAGE(CKM_API_SUCCESS == ec, "add permission failed: " << ec);
}

void readRowExpectFail(DBCrypto & db, const char *alias, const char *accessor_label)
{
    DBCrypto::DBRowOptional row;
    BOOST_REQUIRE_THROW(row = db.getDBRow(alias, accessor_label, DBDataType::BINARY_DATA), DBCrypto::Exception::PermissionDenied);
}

void readRowExpectSuccess(DBCrypto & db, const char *alias, const char *accessor_label)
{
    DBCrypto::DBRowOptional row;
    BOOST_REQUIRE_NO_THROW(row = db.getDBRow(alias, accessor_label, DBDataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(row, "row is empty");
}
}

BOOST_AUTO_TEST_SUITE(DBCRYPTO_TEST)
BOOST_AUTO_TEST_CASE(DBtestSimple) {
    DBCrypto db;
    initDB(db);

    DBRow rowPattern = createDefaultRow();
    rowPattern.data = RawBuffer(32, 1);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    checkDBIntegrity(rowPattern, db);
}
BOOST_AUTO_TEST_CASE(DBtestBIG) {
    DBCrypto db;
    initDB(db);

    DBRow rowPattern = createDefaultRow();
    rowPattern.data = createBigBlob(4096);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    checkDBIntegrity(rowPattern, db);
}
BOOST_AUTO_TEST_CASE(DBtestGlobal) {
    DBCrypto db;
    initDB(db);

    DBRow rowPattern = createDefaultRow();
    rowPattern.data = RawBuffer(1024, 2);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    BOOST_REQUIRE_NO_THROW(db.saveDBRow(rowPattern));

    DBRow alias_duplicate = rowPattern;
    rowPattern.smackLabel = rowPattern.smackLabel + "1";

    BOOST_REQUIRE_THROW(db.saveDBRow(alias_duplicate),
            DBCrypto::Exception::AliasExists);
}
BOOST_AUTO_TEST_CASE(DBtestTransaction) {
    DBCrypto db;
    initDB(db);

    DBRow rowPattern = createDefaultRow();
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);
    DBCrypto::Transaction transaction(&db);

    BOOST_REQUIRE_NO_THROW(db.saveDBRow(rowPattern));
    BOOST_REQUIRE_NO_THROW(transaction.rollback());

    DBCrypto::DBRowOptional row_optional;
    BOOST_REQUIRE_NO_THROW(row_optional = db.getDBRow(default_alias, default_label,
            DBDataType::BINARY_DATA));
    BOOST_CHECK_MESSAGE(!row_optional, "Row still present after rollback");

}

BOOST_AUTO_TEST_CASE(DBaddDataCheckIfPermissionIsAdded)
{
    DBCrypto db;
    initDB(db);

    // insert initial data set
    insertRow(db, row_A_alias, row_A_label);
    insertRow(db, row_B_alias, row_B_label);
    readRowExpectSuccess(db, row_A_alias, row_A_label);
    readRowExpectSuccess(db, row_B_alias, row_B_label);

    // verify that no entries present in the permission table
    // read row A from label B and vice versa
    readRowExpectFail(db, row_A_alias, row_B_label);
    readRowExpectFail(db, row_B_alias, row_A_label);

    // add appropriate permissions for label B
    addPermission(db, row_A_alias, row_A_label, row_B_label);

    // B should have access to A, while A should not to B
    // read row A from label B and vice versa
    readRowExpectSuccess(db, row_A_alias, row_B_label);
    readRowExpectFail(db, row_B_alias, row_A_label);

    // add appropriate permissions for label A
    addPermission(db, row_B_alias, row_B_label, row_A_label);

    // B should have access to A, same as A have access to B
    // read row A from label B and vice versa
    readRowExpectSuccess(db, row_A_alias, row_B_label);
    readRowExpectSuccess(db, row_B_alias, row_A_label);
}


BOOST_AUTO_TEST_CASE(DBremoveDataCheckIfPermissionIsRemoved)
{
    DBCrypto db;
    initDB(db);

    // insert initial data set
    insertRow(db, row_A_alias, row_A_label);
    insertRow(db, row_B_alias, row_B_label);
    insertRow(db, row_C_alias, row_C_label);
    addPermission(db, row_A_alias, row_A_label, row_B_label);
    addPermission(db, row_B_alias, row_B_label, row_A_label);
    // to test multiple permissions removal
    // put intentionally after row_B_alias permission entry
    addPermission(db, row_A_alias, row_A_label, row_C_label);

    // B should have access to A, same as A have access to B
    // read row A from label B and vice versa
    readRowExpectSuccess(db, row_A_alias, row_B_label);
    readRowExpectSuccess(db, row_A_alias, row_C_label);
    readRowExpectSuccess(db, row_B_alias, row_A_label);
    readRowExpectFail(db, row_B_alias, row_C_label);

    // remove data A - expect permissions for B and C to be removed as well
    deleteRow(db, row_A_alias, row_A_label);
    // insert it again - expect permissions for label B and C not to be there anymore
    insertRow(db, row_A_alias, row_A_label);

    // read row A from label B and vice versa
    readRowExpectFail(db, row_A_alias, row_B_label);
    readRowExpectFail(db, row_A_alias, row_C_label);
    readRowExpectSuccess(db, row_B_alias, row_A_label);

    // remove data B - expect permission to be removed as well
    deleteRow(db, row_B_alias, row_B_label);
    // insert it again - expect permissions for label A not to be there anymore
    insertRow(db, row_B_alias, row_B_label);

    // read row A from label B and vice versa
    readRowExpectFail(db, row_A_alias, row_B_label);
    readRowExpectFail(db, row_A_alias, row_C_label);
    readRowExpectFail(db, row_B_alias, row_A_label);

    // sanity check: data exists
    readRowExpectSuccess(db, row_A_alias, row_A_label);
    readRowExpectSuccess(db, row_B_alias, row_B_label);
}


BOOST_AUTO_TEST_SUITE_END()
