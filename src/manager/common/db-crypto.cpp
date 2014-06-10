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

#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

namespace {
    const char *main_table = "CKM_TABLE";

    const char *db_create_cmd =
            "CREATE TABLE CKM_TABLE("
            "   alias TEXT PRIMARY KEY,"
            "   label TEXT NOT NULL,"
            "   restricted INTEGER NOT NULL,"
            "   exportable INTEGER NOT NULL,"
            "   dataType INTEGER NOT NULL,"
            "   algorithmType INTEGER NOT NULL,"
            "   encryptionScheme INTEGER NOT NULL,"
            "   iv BLOB NOT NULL,"
            "   dataSize INTEGER NOT NULL,"
            "   date BLOB NOT NULL"
            ");";

    const char *insert_cmd =
            "INSERT INTO CKM_TABLE("
            //      1   2       3           4
            "   alias, label, restricted, exportable,"
            //      5           6           7
            "   dataType, algorithmType, encryptionScheme,"
            //  8       9       10
            "   iv, dataSize, date) "
            "VALUES("
            "   ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    const char *select_alias_cmd =
            //                                   1
            "SELECT * FROM CKM_TABLE WHERE alias=?;";

    const char *select_type_cmd =
            //                                          1
            "SELECT alias FROM CKM_TABLE WHERE dataType=? AND restricted=0 "
            "UNION ALL "
            //                                          2                            3
            "SELECT alias FROM CKM_TABLE WHERE dataType=? AND restricted=1 AND label=?;";

    const char *delete_alias_cmd =
            "DELETE FROM CKM_TABLE WHERE alias=?;";
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
            m_init = true;
            if(!(m_connection->CheckTableExist(main_table)))
                initDatabase();
        } Catch(SqlConnection::Exception::ConnectionBroken) {
            LogError("Couldn't connect to database: " << path);
        } Catch(SqlConnection::Exception::InvalidArguments) {
            LogError("Couldn't set the key for database");
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

    void DBCrypto::initDatabase() {
        Try {
            m_connection->ExecCommand(db_create_cmd);
            m_init = true;
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't create the main table!");
            m_init = false;
        }
    }

    DBCryptoReturn DBCrypto::saveDBRow(const DBRow &row){
        if(!m_init)
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        Try {
            SqlConnection::DataCommandAutoPtr insertCommand =
                    m_connection->PrepareDataCommand(insert_cmd);
            insertCommand->BindString(1, row.alias.c_str());
            insertCommand->BindString(2, row.smackLabel.c_str());
            insertCommand->BindInteger(3, row.restricted);
            insertCommand->BindInteger(4, row.exportable);
            insertCommand->BindInteger(5, static_cast<int>(row.dataType));
            insertCommand->BindInteger(6, row.algorithmType);
            insertCommand->BindInteger(7, row.encryptionScheme);
            insertCommand->BindBlob(8, row.iv);
            insertCommand->BindInteger(9, row.dataSize);
            insertCommand->BindBlob(10, row.data);

            AssertMsg(insertCommand->Step() == false,
                    "Insert statement should not return any row");
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        }

        return DBCryptoReturn::DBCRYPTO_SUCCESS;
    }

    DBCryptoReturn DBCrypto::getDBRow(const Alias &alias,
                                                   DBRow &row) {

        if(!m_init)
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        Try {
        SqlConnection::DataCommandAutoPtr selectCommand =
                m_connection->PrepareDataCommand(select_alias_cmd);
        selectCommand->BindString(1, alias.c_str());

        if(selectCommand->Step()) {
            row.alias = selectCommand->GetColumnString(1);
            row.smackLabel = selectCommand->GetColumnString(2);
            row.restricted = selectCommand->GetColumnInteger(3);
            row.exportable = selectCommand->GetColumnInteger(4);
            row.dataType = static_cast<DBDataType>(selectCommand->GetColumnInteger(5));
            row.algorithmType = selectCommand->GetColumnInteger(6);
            row.encryptionScheme = selectCommand->GetColumnInteger(7);
            row.iv = selectCommand->GetColumnBlob(8);
            row.dataSize = selectCommand->GetColumnInteger(9);
            row.data = selectCommand->GetColumnBlob(10);
        } else {
            return DBCryptoReturn::DBCRYPTO_ERROR_NO_ROW;
        }

        AssertMsg(!selectCommand->Step(),
                "Select returned multiple rows for unique column.");
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        }
        return DBCryptoReturn::DBCRYPTO_SUCCESS;
    }

    DBCryptoReturn DBCrypto::getSingleType(DBDataType type, const std::string& label,
            AliasVector& aliases) {
        Try{
            SqlConnection::DataCommandAutoPtr selectCommand =
                            m_connection->PrepareDataCommand(select_type_cmd);
            selectCommand->BindInteger(1, static_cast<int>(type));
            selectCommand->BindInteger(2, static_cast<int>(type));
            selectCommand->BindString(3, label.c_str());

            while(selectCommand->Step()) {
                Alias alias;
                alias = selectCommand->GetColumnString(1);
                aliases.push_back(alias);
            }
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        }
        return DBCryptoReturn::DBCRYPTO_SUCCESS;
    }

    DBCryptoReturn DBCrypto::getAliases(DBQueryType type, const std::string& label,
            AliasVector& aliases) {

        if(!m_init)
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        DBCryptoReturn ret;
        switch(type) {
        case DBQueryType::KEY_QUERY:
            ret = getSingleType(DBDataType::KEY_AES, label, aliases);
            if(ret != DBCryptoReturn::DBCRYPTO_SUCCESS)
                return ret;
            ret = getSingleType(DBDataType::KEY_ECDSA_PRIVATE, label, aliases);
            if(ret != DBCryptoReturn::DBCRYPTO_SUCCESS)
                return ret;
            ret = getSingleType(DBDataType::KEY_ECDSA_PUBLIC, label, aliases);
            if(ret != DBCryptoReturn::DBCRYPTO_SUCCESS)
                return ret;
            ret = getSingleType(DBDataType::KEY_RSA_PRIVATE, label, aliases);
            if(ret != DBCryptoReturn::DBCRYPTO_SUCCESS)
                return ret;
            return(getSingleType(DBDataType::KEY_RSA_PUBLIC, label, aliases));
        case DBQueryType::CERTIFICATE_QUERY:
            return getSingleType(DBDataType::CERTIFICATE, label, aliases);
        case DBQueryType::BINARY_DATA_QUERY:
            return getSingleType(DBDataType::BINARY_DATA, label, aliases);
        }
        return DBCryptoReturn::DBCRYPTO_SUCCESS;
    }

    DBCryptoReturn DBCrypto::deleteAlias(const Alias &alias) {
        Try {
            SqlConnection::DataCommandAutoPtr deleteCommand =
                    m_connection->PrepareDataCommand(delete_alias_cmd);
            deleteCommand->BindString(1, alias.c_str());
            deleteCommand->Step();
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare delete statement");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute delete statement");
            return DBCryptoReturn::DBCRYPTO_ERROR_INTERNAL;
        }
        return DBCryptoReturn::DBCRYPTO_SUCCESS;
    }

} // CKM

#pragma GCC diagnostic pop
