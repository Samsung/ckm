#pragma once

#include <test_common.h>
#include <ckm/ckm-type.h>
#include <chrono>

class DBFixture
{
    public:
        DBFixture();

        constexpr static const char* m_default_alias = "alias";
        constexpr static const char* m_default_label = "label";

        // ::::::::::::::::::::::::: helper methods :::::::::::::::::::::::::
        static void generate_alias(unsigned int id, std::string & output);
        static void generate_label(unsigned int id, std::string & output);
        static CKM::DBRow create_default_row(CKM::DBDataType type = CKM::DBDataType::BINARY_DATA);
        static CKM::DBRow create_default_row(const std::string &alias,
                                             const std::string &label,
                                             CKM::DBDataType type = CKM::DBDataType::BINARY_DATA);
        static void compare_row(const CKM::DBRow &lhs, const CKM::DBRow &rhs);

        // ::::::::::::::::::::::::: time measurement :::::::::::::::::::::::::
        void performance_start(const char *operation_name);
        void performance_stop(long num_operations_performed);

        // ::::::::::::::::::::::::: DB :::::::::::::::::::::::::
        void generate_perf_DB(unsigned int num_alias, unsigned int num_label);
        long add_full_access_rights(unsigned int num_alias, unsigned int num_alias_per_label);
        void check_DB_integrity(const CKM::DBRow &rowPattern);
        void insert_row();
        void insert_row(const std::string &alias, const std::string &accessor_label);
        void delete_row(const std::string &alias, const std::string &accessor_label);
        void add_permission(const std::string &alias, const std::string &owner_label, const std::string &accessor_label);
        void read_row_expect_fail(const std::string &alias, const std::string &accessor_label);
        void read_row_expect_success(const std::string &alias, const std::string &accessor_label);

        CKM::DBCrypto    m_db;
    private:
        double  performance_get_time_elapsed_ms();

        constexpr static const char* m_crypto_db_fname = "/tmp/testme.db";
        std::string m_operation;
        std::chrono::high_resolution_clock::time_point m_start_time, m_end_time;
};