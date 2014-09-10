#include <boost/test/unit_test.hpp>
#include <boost/test/results_reporter.hpp>
#include <unistd.h>
#include <db-crypto.h>
#include <iostream>
#include <ckm/ckm-error.h>
#include <errno.h>

#include <test_common.h>

BOOST_GLOBAL_FIXTURE(TestConfig)

using namespace CKM;

const char* default_alias = "alias";
const char* default_label = "label";

const char* crypto_db = "/tmp/testme.db";

const int restricted_local = 1;
const int restricted_global = 0;

DBRow createDefaultRow(DBDataType type = DBDataType::BINARY_DATA) {
    DBRow row;
    row.alias = default_alias;
    row.smackLabel = default_label;
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

BOOST_AUTO_TEST_SUITE(DBCRYPTO_TEST)
BOOST_AUTO_TEST_CASE(DBtestSimple) {

    BOOST_CHECK(unlink(crypto_db) == 0 || errno == ENOENT);
    DBCrypto db;
    BOOST_REQUIRE_NO_THROW(db = DBCrypto(crypto_db, defaultPass));

    DBRow rowPattern = createDefaultRow();
    rowPattern.data = RawBuffer(32, 1);
    rowPattern.dataSize = rowPattern.data.size();

    checkDBIntegrity(rowPattern, db);
}
BOOST_AUTO_TEST_CASE(DBtestBIG) {
    BOOST_CHECK(unlink(crypto_db) == 0 || errno == ENOENT);
    DBCrypto db;
    BOOST_REQUIRE_NO_THROW(db = DBCrypto(crypto_db, defaultPass));

    DBRow rowPattern = createDefaultRow();
    rowPattern.data = createBigBlob(4096);
    rowPattern.dataSize = rowPattern.data.size();

    checkDBIntegrity(rowPattern, db);
}
BOOST_AUTO_TEST_CASE(DBtestGlobal) {
    BOOST_CHECK(unlink(crypto_db) == 0 || errno == ENOENT);
    DBCrypto db;
    BOOST_REQUIRE_NO_THROW(db = DBCrypto(crypto_db, defaultPass));

    DBRow rowPattern = createDefaultRow();
    rowPattern.data = RawBuffer(1024, 2);
    rowPattern.dataSize = rowPattern.data.size();

    BOOST_REQUIRE_NO_THROW(db.saveDBRow(rowPattern));

    DBRow alias_duplicate = rowPattern;
    rowPattern.smackLabel = rowPattern.smackLabel + "1";

    BOOST_REQUIRE_THROW(db.saveDBRow(alias_duplicate),
            DBCrypto::Exception::AliasExists);
}
BOOST_AUTO_TEST_CASE(DBtestTransaction) {
    BOOST_CHECK(unlink(crypto_db) == 0 || errno == ENOENT);
    DBCrypto db;
    BOOST_REQUIRE_NO_THROW(db = DBCrypto(crypto_db, defaultPass));

    DBRow rowPattern = createDefaultRow();
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    DBCrypto::Transaction transaction(&db);

    BOOST_REQUIRE_NO_THROW(db.saveDBRow(rowPattern));
    BOOST_REQUIRE_NO_THROW(transaction.rollback());

    DBCrypto::DBRowOptional row_optional;
    BOOST_REQUIRE_NO_THROW(row_optional = db.getDBRow(default_alias, default_label,
            DBDataType::BINARY_DATA));
    BOOST_CHECK_MESSAGE(!row_optional, "Row still present after rollback");

}
BOOST_AUTO_TEST_SUITE_END()
