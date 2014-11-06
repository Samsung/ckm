#include <boost/test/unit_test.hpp>
#include <db-crypto.h>
#include <ckm/ckm-error.h>
#include <DBFixture.h>

using namespace CKM;
using namespace std::chrono;


DBFixture::DBFixture()
{
    high_resolution_clock::time_point srand_feed = high_resolution_clock::now();
    srand(srand_feed.time_since_epoch().count());

    BOOST_CHECK(unlink(m_crypto_db_fname) == 0 || errno == ENOENT);
    BOOST_REQUIRE_NO_THROW(m_db = DBCrypto(m_crypto_db_fname, defaultPass));
}

double DBFixture::performance_get_time_elapsed_ms()
{
    return duration_cast<milliseconds>(m_end_time - m_start_time).count();
}

void DBFixture::performance_start(const char *operation_name)
{
    m_operation = std::string(operation_name?operation_name:"unknown");
    BOOST_TEST_MESSAGE("\t<performance> running " << m_operation << " performance test...");
    m_start_time = high_resolution_clock::now();
}

void DBFixture::performance_stop(long num_operations_performed)
{
    m_end_time = high_resolution_clock::now();
    double time_elapsed_ms = performance_get_time_elapsed_ms();
    BOOST_TEST_MESSAGE("\t<performance> time elapsed: " << time_elapsed_ms << "[ms], number of " << m_operation << ": " << num_operations_performed);
    if(num_operations_performed>0)
        BOOST_TEST_MESSAGE("\t<performance> average time per " << m_operation << ": " << time_elapsed_ms/num_operations_performed << "[ms]");
}

void DBFixture::generate_name(unsigned int id, Name & output)
{
    std::stringstream ss;
    ss << "name_no_" << id;
    output = ss.str();
}

void DBFixture::generate_label(unsigned int id, Label & output)
{
    std::stringstream ss;
    ss << "label_no_" << id;
    output = ss.str();
}

void DBFixture::generate_perf_DB(unsigned int num_name, unsigned int num_label)
{
    // to speed up data creation - cache the row
    DBRow rowPattern = create_default_row(DBDataType::BINARY_DATA);
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    for(unsigned int i=0; i<num_name; i++)
    {
        generate_name(i, rowPattern.name);
        generate_label(i/num_label, rowPattern.ownerLabel);

        BOOST_REQUIRE_NO_THROW(m_db.saveDBRow(rowPattern));
    }
}

long DBFixture::add_full_access_rights(unsigned int num_name, unsigned int num_name_per_label)
{
    long iterations = 0;
    unsigned int num_labels = num_name / num_name_per_label;
    Name name;
    Label owner_label, accessor_label;
    for(unsigned int a=0; a<num_name; a++)
    {
        generate_name(a, name);
        generate_label(a/num_name_per_label, owner_label);
        for(unsigned int l=0; l<num_labels; l++)
        {
            // bypass the owner label
            if(l == (a/num_name_per_label))
                continue;

            // add permission
            generate_label(l, accessor_label);
            add_permission(name, owner_label, accessor_label);
            iterations ++;
        }
    }

    return iterations;
}

DBRow DBFixture::create_default_row(DBDataType type)
{
    return create_default_row(m_default_name, m_default_label, type);
}

DBRow DBFixture::create_default_row(const Name &name,
                                    const Label &label,
                                    DBDataType type)
{
    DBRow row;
    row.name = name;
    row.ownerLabel = label;
    row.exportable = 1;
    row.algorithmType = DBCMAlgType::AES_GCM_256;
    row.dataType = type;
    row.iv = createDefaultPass();
    row.encryptionScheme = 0;
    row.dataSize = 0;

    return row;
}

void DBFixture::compare_row(const DBRow &lhs, const DBRow &rhs)
{
    BOOST_CHECK_MESSAGE(lhs.name == rhs.name,
            "namees didn't match! Got: " << rhs.name
                << " , expected : " << lhs.name);

    BOOST_CHECK_MESSAGE(lhs.ownerLabel == rhs.ownerLabel,
            "smackLabel didn't match! Got: " << rhs.ownerLabel
                << " , expected : " << lhs.ownerLabel);

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

void DBFixture::check_DB_integrity(const DBRow &rowPattern)
{
    BOOST_REQUIRE_NO_THROW(m_db.saveDBRow(rowPattern));
    DBRow selectRow = rowPattern;

    DBCrypto::DBRowOptional optional_row;
    BOOST_REQUIRE_NO_THROW(optional_row = m_db.getDBRow("name", "label", DBDataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(optional_row, "Select didn't return any row");

    compare_row(selectRow, rowPattern);
    DBRow name_duplicate = rowPattern;
    name_duplicate.data = createDefaultPass();
    name_duplicate.dataSize = name_duplicate.data.size();

    unsigned int erased;
    BOOST_REQUIRE_NO_THROW(erased = m_db.deleteDBRow("name", "label"));
    BOOST_REQUIRE_MESSAGE(erased > 0, "Inserted row didn't exist in db");

    DBCrypto::DBRowOptional row_optional;
    BOOST_REQUIRE_NO_THROW(row_optional = m_db.getDBRow("name", "label", DBDataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(!row_optional, "Select should not return row after deletion");
}

void DBFixture::insert_row()
{
    insert_row(m_default_name, m_default_label);
}

void DBFixture::insert_row(const Name &name, const Label &owner_label)
{
    DBRow rowPattern = create_default_row(name, owner_label, DBDataType::BINARY_DATA);
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);
    BOOST_REQUIRE_NO_THROW(m_db.saveDBRow(rowPattern));
}

void DBFixture::delete_row(const Name &name, const Label &owner_label)
{
    bool exit_flag;
    BOOST_REQUIRE_NO_THROW(exit_flag = m_db.deleteDBRow(name, owner_label));
    BOOST_REQUIRE_MESSAGE(true == exit_flag, "remove name failed: no rows removed");
}

void DBFixture::add_permission(const Name &name, const Label &owner_label, const Label &accessor_label)
{
    int ec;
    BOOST_REQUIRE_NO_THROW(ec = m_db.setPermission(name,
                                                     owner_label,
                                                     accessor_label,
                                                     CKM::Permission::READ_REMOVE));
    BOOST_REQUIRE_MESSAGE(CKM_API_SUCCESS == ec, "add permission failed: " << ec);
}

void DBFixture::read_row_expect_success(const Name &name, const Label &owner_label)
{
    DBCrypto::DBRowOptional row;
    BOOST_REQUIRE_NO_THROW(row = m_db.getDBRow(name, owner_label, DBDataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(row, "row is empty");
    BOOST_REQUIRE_MESSAGE(row->name == name, "name is not valid");
}
