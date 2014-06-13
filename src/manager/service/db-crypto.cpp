/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        db-crypto.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of encrypted db access layer
 */

#include <db-crypto.h>
#include <dpl/db/sql_connection.h>
#include <dpl/log/log.h>
#include <ckm/ckm-error.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

namespace {
    const char *main_table = "CKM_TABLE";
    const char *key_table = "KEY_TABLE";

// CKM_TABLE (alias TEXT, label TEXT, restricted INT, exportable INT, dataType INT,
//            algorithmType INT, encryptionScheme INT, iv BLOB, dataSize INT, data BLOB)

    const char *db_create_main_cmd =
            "CREATE TABLE CKM_TABLE("
            "   alias TEXT NOT NULL,"
            "   label TEXT NOT NULL,"
            "   restricted INTEGER NOT NULL,"
            "   exportable INTEGER NOT NULL,"
            "   dataType INTEGER NOT NULL,"
            "   algorithmType INTEGER NOT NULL,"
            "   encryptionScheme INTEGER NOT NULL,"
            "   iv BLOB NOT NULL,"
            "   dataSize INTEGER NOT NULL,"
            "   data BLOB NOT NULL,"
            "   PRIMARY KEY(alias, label)"
            ");";


    const char *insert_main_cmd =
            "INSERT INTO CKM_TABLE("
            //      1   2       3           4
            "   alias, label, restricted, exportable,"
            //      5           6           7
            "   dataType, algorithmType, encryptionScheme,"
            //  8       9       10
            "   iv, dataSize, data) "
            "VALUES("
            "   ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    const char *select_alias_cmd =
            //                                   1           2              3
            "SELECT * FROM CKM_TABLE WHERE alias=? AND label=? AND dataType=?;";

    const char *select_key_alias_cmd =
            "SELECT * FROM CKM_TABLE WHERE alias=? AND label=? "
            " AND dataType BETWEEN ? AND ?;";

    const char *select_key_type_cmd =
            "SELECT alias FROM CKM_TABLE WHERE "
                " dataType >= ? AND "
                " dataType <= ? AND "
                " (restricted=0 OR label=?)";

    const char *select_type_cmd =
            //                                          1
            "SELECT alias FROM CKM_TABLE WHERE dataType=? AND restricted=0 "
            "UNION ALL "
            //                                          2                            3
            "SELECT alias FROM CKM_TABLE WHERE dataType=? AND restricted=1 AND label=?;";

    const char *delete_alias_cmd =
            //                                 1           2
            "DELETE FROM CKM_TABLE WHERE alias=? AND label=?;";

// KEY_TABLE (label TEXT, key BLOB)

    const char *db_create_key_cmd =
            "CREATE TABLE KEY_TABLE("
            "   label TEXT PRIMARY KEY,"
            "   key BLOB NOT NULL"
            ");";

    const char *insert_key_cmd =
            "INSERT INTO KEY_TABLE(label, key) VALUES (?, ?);";
    const char *select_key_cmd =
            "SELECT key FROM KEY_TABLE WHERE label=?;";
    const char *delete_key_cmd =
            "DELETE FROM KEY_TABLE WHERE label=?";
}

namespace CKM {
using namespace DB;
    DBCrypto::DBCrypto(const std::string& path,
                         const RawBuffer &rawPass) {
        m_connection = NULL;
        m_init = false;
        Try {
            m_connection = new SqlConnection(path, SqlConnection::Flag::Option::CRW);
            m_connection->SetKey(rawPass);
            initDatabase();
            m_init = true;
        } Catch(SqlConnection::Exception::ConnectionBroken) {
            LogError("Couldn't connect to database: " << path);
        } Catch(SqlConnection::Exception::InvalidArguments) {
            LogError("Couldn't set the key for database");
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't initiate the database");
        }
    }

    DBCrypto::DBCrypto(DBCrypto &&other) :
            m_connection(other.m_connection),
            m_init(other.m_init) {
        other.m_connection = NULL;
        other.m_init = false;
    }

    DBCrypto::~DBCrypto() {
        delete m_connection;
    }

    DBCrypto& DBCrypto::operator=(DBCrypto&& other) {
        if (this == &other)
            return *this;
        delete m_connection;

        m_connection = other.m_connection;
        other.m_connection = NULL;

        m_init = other.m_init;
        other.m_init = false;

        return *this;
    }

    void DBCrypto::createTable(const char* create_cmd) {
        Try {
            m_connection->ExecCommand(create_cmd);
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't create the main table!");
            throw;
        }
    }

    void DBCrypto::initDatabase() {

        if(!m_connection->CheckTableExist(main_table)) {
            createTable(db_create_main_cmd);
        }
        if(!m_connection->CheckTableExist(key_table)) {
            createTable(db_create_key_cmd);
        }
    }

    int DBCrypto::saveDBRow(const DBRow &row){
        if(!m_init)
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        Try {
            SqlConnection::DataCommandAutoPtr insertCommand =
                    m_connection->PrepareDataCommand(insert_main_cmd);
            insertCommand->BindString(1, row.alias.c_str());
            insertCommand->BindString(2, row.smackLabel.c_str());
            insertCommand->BindInteger(3, row.restricted);
            insertCommand->BindInteger(4, row.exportable);
            insertCommand->BindInteger(5, static_cast<int>(row.dataType));
            insertCommand->BindInteger(6, static_cast<int>(row.algorithmType));
            insertCommand->BindInteger(7, row.encryptionScheme);
            insertCommand->BindBlob(8, row.iv);
            insertCommand->BindInteger(9, row.dataSize);
            insertCommand->BindBlob(10, row.data);

            AssertMsg(insertCommand->Step() == false,
                    "Insert statement should not return any row");
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }

        return KEY_MANAGER_API_SUCCESS;
    }

    DBRow DBCrypto::getRow(const SqlConnection::DataCommandAutoPtr &selectCommand) {
        DBRow row;
        row.alias = selectCommand->GetColumnString(0);
        row.smackLabel = selectCommand->GetColumnString(1);
        row.restricted = selectCommand->GetColumnInteger(2);
        row.exportable = selectCommand->GetColumnInteger(3);
        row.dataType = static_cast<DBDataType>(selectCommand->GetColumnInteger(4));
        row.algorithmType = static_cast<DBCMAlgType>(selectCommand->GetColumnInteger(5));
        row.encryptionScheme = selectCommand->GetColumnInteger(6);
        row.iv = selectCommand->GetColumnBlob(7);
        row.dataSize = selectCommand->GetColumnInteger(8);
        row.data = selectCommand->GetColumnBlob(9);
        return row;
    }

    int DBCrypto::getDBRow(
        const Alias &alias,
        const std::string &label,
        DBDataType type,
        DBRow &row)
    {
        if(!m_init)
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        Try {
        SqlConnection::DataCommandAutoPtr selectCommand =
                m_connection->PrepareDataCommand(select_alias_cmd);
        selectCommand->BindString(1, alias.c_str());
        selectCommand->BindString(2, label.c_str());
        selectCommand->BindInteger(3, static_cast<int>(type));

        if(selectCommand->Step()) {
            row = getRow(selectCommand);
        } else {
            return KEY_MANAGER_API_ERROR_DB_BAD_REQUEST;
        }

        AssertMsg(!selectCommand->Step(),
                "Select returned multiple rows for unique column.");
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }
        return KEY_MANAGER_API_SUCCESS;
    }

    int DBCrypto::getKeyDBRow(
        const Alias &alias,
        const std::string &label,
        DBRow &row) {
        if (!m_init)
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        Try{
            SqlConnection::DataCommandAutoPtr selectCommand =
                    m_connection->PrepareDataCommand(select_key_alias_cmd);
            selectCommand->BindString(1, alias.c_str());
            selectCommand->BindString(2, label.c_str());
            selectCommand->BindInteger(3, static_cast<int>(DBDataType::DB_KEY_FIRST));
            selectCommand->BindInteger(4, static_cast<int>(DBDataType::DB_KEY_LAST));

            if(selectCommand->Step()){
                row = getRow(selectCommand);
            } else {
                return KEY_MANAGER_API_ERROR_DB_BAD_REQUEST;
            }
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }
        return KEY_MANAGER_API_SUCCESS;
    }

    int DBCrypto::getSingleType(
            DBDataType type,
            const std::string& label,
            AliasVector& aliases)
    {
        Try{
            SqlConnection::DataCommandAutoPtr selectCommand =
                            m_connection->PrepareDataCommand(select_type_cmd);
            selectCommand->BindInteger(1, static_cast<int>(type));
            selectCommand->BindInteger(2, static_cast<int>(type));
            selectCommand->BindString(3, label.c_str());

            while(selectCommand->Step()) {
                Alias alias;
                alias = selectCommand->GetColumnString(0);
                aliases.push_back(alias);
            }
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }
        return KEY_MANAGER_API_SUCCESS;
    }

    int DBCrypto::getAliases(
        DBDataType type,
        const std::string& label,
        AliasVector& aliases)
    {
        if(!m_init)
            return KEY_MANAGER_API_ERROR_DB_ERROR;

        return getSingleType(type, label, aliases);
    }


    int DBCrypto::getKeyAliases(
        const std::string &label,
        AliasVector &aliases)
    {
        if (!m_init)
            return KEY_MANAGER_API_ERROR_DB_ERROR;

        Try{
            SqlConnection::DataCommandAutoPtr selectCommand =
                            m_connection->PrepareDataCommand(select_key_type_cmd);
            selectCommand->BindInteger(1, static_cast<int>(DBDataType::DB_KEY_FIRST));
            selectCommand->BindInteger(2, static_cast<int>(DBDataType::DB_KEY_LAST));
            selectCommand->BindString(3, label.c_str());

            while(selectCommand->Step()) {
                Alias alias;
                alias = selectCommand->GetColumnString(0);
                aliases.push_back(alias);
            }
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }
        return KEY_MANAGER_API_SUCCESS;
    }

    int DBCrypto::deleteDBRow(
            const Alias &alias,
            const std::string &label)
    {
        Try {
            SqlConnection::DataCommandAutoPtr deleteCommand =
                    m_connection->PrepareDataCommand(delete_alias_cmd);
            deleteCommand->BindString(1, alias.c_str());
            deleteCommand->BindString(2, label.c_str());
            deleteCommand->Step();
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare delete statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute delete statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }
        return KEY_MANAGER_API_SUCCESS;
    }

    int DBCrypto::saveKey(
            const std::string& label,
            const RawBuffer &key)
    {
        if (!m_init)
            return KEY_MANAGER_API_ERROR_DB_ERROR;

        Try {
            SqlConnection::DataCommandAutoPtr insertCommand =
                    m_connection->PrepareDataCommand(insert_key_cmd);
            insertCommand->BindString(1, label.c_str());
            insertCommand->BindBlob(2, key);

            insertCommand->Step();

        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert key statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }

        return KEY_MANAGER_API_SUCCESS;
    }
    int DBCrypto::getKey(
            const std::string& label,
            RawBuffer &key)
    {
        if (!m_init)
            return KEY_MANAGER_API_ERROR_DB_ERROR;

        Try {
            SqlConnection::DataCommandAutoPtr selectCommand =
                    m_connection->PrepareDataCommand(select_key_cmd);
            selectCommand->BindString(1, label.c_str());

            if (selectCommand->Step()) {
                key = selectCommand->GetColumnBlob(0);
            } else {
                return KEY_MANAGER_API_ERROR_DB_BAD_REQUEST;
            }

            AssertMsg(!selectCommand->Step(),
                "Select returned multiple rows for unique column.");

        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert key statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }
        return KEY_MANAGER_API_SUCCESS;
    }
    int DBCrypto::deleteKey(const std::string& label) {
        if (!m_init)
            return KEY_MANAGER_API_ERROR_DB_ERROR;

        Try {
            SqlConnection::DataCommandAutoPtr deleteCommand =
                    m_connection->PrepareDataCommand(delete_key_cmd);
            deleteCommand->BindString(1, label.c_str());

            deleteCommand->Step();

        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert key statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
            return KEY_MANAGER_API_ERROR_DB_ERROR;
        }
        return KEY_MANAGER_API_SUCCESS;
    }

} // CKM

#pragma GCC diagnostic pop
