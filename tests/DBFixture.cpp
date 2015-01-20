#include <boost/test/unit_test.hpp>
#include <db-crypto.h>
#include <ckm/ckm-error.h>
#include <DBFixture.h>
#include <fstream>

using namespace CKM;
using namespace std::chrono;


DBFixture::DBFixture()
{
    BOOST_CHECK(unlink(m_crypto_db_fname) == 0 || errno == ENOENT);
    init();
}
DBFixture::DBFixture(const char *db_fname)
{
    BOOST_CHECK(unlink(m_crypto_db_fname) == 0 || errno == ENOENT);

    // copy file
    std::ifstream f1(db_fname, std::fstream::binary);
    std::ofstream f2(m_crypto_db_fname, std::fstream::trunc|std::fstream::binary);
    f2 << f1.rdbuf();
    f2.close();
    f1.close();

    init();
}

void DBFixture::init()
{
    high_resolution_clock::time_point srand_feed = high_resolution_clock::now();
    srand(srand_feed.time_since_epoch().count());

    BOOST_REQUIRE_NO_THROW(m_db = DB::Crypto(m_crypto_db_fname, defaultPass));
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

void DBFixture::generate_perf_DB(unsigned int num_name, unsigned int num_elements)
{
    // to speed up data creation - cache the row
    DB::Row rowPattern = create_default_row(DataType::BINARY_DATA);
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);

    for(unsigned int i=0; i<num_name; i++)
    {
        generate_name(i, rowPattern.name);
        generate_label(i/num_elements, rowPattern.ownerLabel);

        BOOST_REQUIRE_NO_THROW(m_db.saveRow(rowPattern));
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

DB::Row DBFixture::create_default_row(DataType type)
{
    return create_default_row(m_default_name, m_default_label, type);
}

DB::Row DBFixture::create_default_row(const Name &name,
                                    const Label &label,
                                    DataType type)
{
    DB::Row row;
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

void DBFixture::compare_row(const DB::Row &lhs, const DB::Row &rhs)
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

void DBFixture::check_DB_integrity(const DB::Row &rowPattern)
{
    BOOST_REQUIRE_NO_THROW(m_db.saveRow(rowPattern));
    DB::Row selectRow = rowPattern;

    DB::Crypto::RowOptional optional_row;
    BOOST_REQUIRE_NO_THROW(optional_row = m_db.getRow("name", "label", DataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(optional_row, "Select didn't return any row");

    compare_row(selectRow, rowPattern);
    DB::Row name_duplicate = rowPattern;
    name_duplicate.data = createDefaultPass();
    name_duplicate.dataSize = name_duplicate.data.size();

    unsigned int erased;
    BOOST_REQUIRE_NO_THROW(erased = m_db.deleteRow("name", "label"));
    BOOST_REQUIRE_MESSAGE(erased > 0, "Inserted row didn't exist in db");

    DB::Crypto::RowOptional row_optional;
    BOOST_REQUIRE_NO_THROW(row_optional = m_db.getRow("name", "label", DataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(!row_optional, "Select should not return row after deletion");
}

void DBFixture::insert_row()
{
    insert_row(m_default_name, m_default_label);
}

void DBFixture::insert_row(const Name &name, const Label &owner_label)
{
    DB::Row rowPattern = create_default_row(name, owner_label, DataType::BINARY_DATA);
    rowPattern.data = RawBuffer(100, 20);
    rowPattern.dataSize = rowPattern.data.size();
    rowPattern.tag = RawBuffer(AES_GCM_TAG_SIZE, 1);
    BOOST_REQUIRE_NO_THROW(m_db.saveRow(rowPattern));
}

void DBFixture::delete_row(const Name &name, const Label &owner_label)
{
    bool exit_flag;
    BOOST_REQUIRE_NO_THROW(exit_flag = m_db.deleteRow(name, owner_label));
    BOOST_REQUIRE_MESSAGE(true == exit_flag, "remove name failed: no rows removed");
}

void DBFixture::add_permission(const Name &name, const Label &owner_label, const Label &accessor_label)
{
    BOOST_REQUIRE_NO_THROW(m_db.setPermission(name,
                                              owner_label,
                                              accessor_label,
                                              CKM::Permission::READ | CKM::Permission::REMOVE));
}

void DBFixture::read_row_expect_success(const Name &name, const Label &owner_label)
{
    DB::Crypto::RowOptional row;
    BOOST_REQUIRE_NO_THROW(row = m_db.getRow(name, owner_label, DataType::BINARY_DATA));
    BOOST_REQUIRE_MESSAGE(row, "row is empty");
    BOOST_REQUIRE_MESSAGE(row->name == name, "name is not valid");
}
