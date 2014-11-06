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
    const char *permission_table = "PERMISSION_TABLE";

// CKM_TABLE (name TEXT, label TEXT, restricted INT, exportable INT, dataType INT, algorithmType INT,
//            encryptionScheme INT, iv BLOB, dataSize INT, data BLOB, tag BLOB, idx INT )

    const char *db_create_main_cmd =
            "CREATE TABLE CKM_TABLE("
            "   name TEXT NOT NULL,"
            "   label TEXT NOT NULL,"
            "   exportable INTEGER NOT NULL,"
            "   dataType INTEGER NOT NULL,"
            "   algorithmType INTEGER NOT NULL,"
            "   encryptionScheme INTEGER NOT NULL,"
            "   iv BLOB NOT NULL,"
            "   dataSize INTEGER NOT NULL,"
            "   data BLOB NOT NULL,"
            "   tag BLOB NOT NULL,"
            "   idx INTEGER PRIMARY KEY AUTOINCREMENT,"
            "   UNIQUE(name, label)"
            "); CREATE INDEX ckm_index_label ON CKM_TABLE(label);"; // based on ANALYZE and performance test result

    const char *insert_main_cmd =
            "INSERT INTO CKM_TABLE("
            //      1   2       3
            "   name, label, exportable,"
            //      4           5           6
            "   dataType, algorithmType, encryptionScheme,"
            //  7       8       9    10
            "   iv, dataSize, data, tag) "
            "VALUES("
            "   ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    const char *select_check_name_cmd =
            "SELECT dataType FROM CKM_TABLE WHERE name=?001 AND label=?002;";

    const char *select_row_by_name_label_type_cmd =
            "SELECT * FROM CKM_TABLE WHERE name=?001 AND label=?002"
            " AND dataType BETWEEN ?003 AND ?004;";

    const char *select_count_rows_cmd =
            "SELECT COUNT(idx) FROM CKM_TABLE WHERE name=?001 AND label=?002;";

    const char *delete_name_cmd =
            "DELETE FROM CKM_TABLE WHERE name=?001 AND label=?002;";

    const char *delete_data_with_key_cmd =
            //                                 1
            "DELETE FROM CKM_TABLE WHERE label=?;";

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


// PERMISSION_TABLE (label TEXT, access_flags TEXT, idx INT)

    const char *db_create_permission_cmd =
            "CREATE TABLE PERMISSION_TABLE("
            "   label TEXT NOT NULL,"
            "   accessFlags TEXT NOT NULL,"
            "   idx INTEGER NOT NULL,"
            "   FOREIGN KEY(idx) REFERENCES CKM_TABLE(idx) ON DELETE CASCADE,"
            "   PRIMARY KEY(label, idx)"
            "); CREATE INDEX perm_index_idx ON PERMISSION_TABLE(idx);"; // based on ANALYZE and performance test result

    const char *set_permission_name_cmd =
            "REPLACE INTO PERMISSION_TABLE(label, accessFlags, idx) "
            " VALUES (?001, ?002, "
            " (SELECT idx FROM CKM_TABLE WHERE name = ?003 and label = ?004)); ";

    const char *select_permission_cmd =
            "SELECT accessFlags FROM PERMISSION_TABLE WHERE label=?001 AND idx IN (SELECT idx FROM CKM_TABLE WHERE name=?002 AND label=?003);";

    const char *delete_permission_cmd =
            "DELETE FROM PERMISSION_TABLE WHERE label=?003 AND "
            " idx IN (SELECT idx FROM CKM_TABLE WHERE name = ?001 AND label = ?002); ";


// CKM_TABLE x PERMISSION_TABLE

    const char *select_key_type_cross_cmd =
            "SELECT C.label, C.name FROM CKM_TABLE AS C LEFT JOIN PERMISSION_TABLE AS P ON C.idx=P.idx WHERE "
            " C.dataType>=?001 AND C.dataType<=?002 AND "
            "(C.label=?003 OR (P.label=?003 AND P.accessFlags IS NOT NULL)) GROUP BY C.name; ";
}

namespace CKM {
using namespace DB;
    DBCrypto::DBCrypto(const std::string& path,
                         const RawBuffer &rawPass) {
        m_connection = NULL;
        m_inUserTransaction = false;
        Try {
            m_connection = new SqlConnection(path, SqlConnection::Flag::Option::CRW);
            m_connection->SetKey(rawPass);
            m_connection->ExecCommand("VACUUM;");
            initDatabase();
        } Catch(SqlConnection::Exception::ConnectionBroken) {
            LogError("Couldn't connect to database: " << path);
            ReThrow(DBCrypto::Exception::InternalError);
        } Catch(SqlConnection::Exception::InvalidArguments) {
            LogError("Couldn't set the key for database");
            ReThrow(DBCrypto::Exception::InternalError);
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't initiate the database");
            ReThrow(DBCrypto::Exception::InternalError);
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't create the database");
            ReThrow(DBCrypto::Exception::InternalError);
        }
    }

    DBCrypto::DBCrypto(DBCrypto &&other) :
            m_connection(other.m_connection),
            m_inUserTransaction(other.m_inUserTransaction){
        other.m_connection = NULL;
        other.m_inUserTransaction = false;
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

        m_inUserTransaction = other.m_inUserTransaction;
        other.m_inUserTransaction = false;

        return *this;
    }

    void DBCrypto::createTable(
            const char* create_cmd,
            const char *table_name)
    {
        Try {
            m_connection->ExecCommand(create_cmd);
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't create table : " << table_name << "!");
            throw;
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Sqlite got into infinite busy state");
            throw;
        }
    }

    void DBCrypto::initDatabase() {
        Transaction transaction(this);
        if(!m_connection->CheckTableExist(main_table)) {
            createTable(db_create_main_cmd, main_table);
        }
        if(!m_connection->CheckTableExist(key_table)) {
            createTable(db_create_key_cmd, key_table);
        }
        if(!m_connection->CheckTableExist(permission_table)) {
            createTable(db_create_permission_cmd, permission_table);
        }
        transaction.commit();
    }

    bool DBCrypto::isNameLabelPresent(const Name &name, const Label &owner) const {
        Try {
            SqlConnection::DataCommandUniquePtr checkCmd =
                    m_connection->PrepareDataCommand(select_check_name_cmd);
            checkCmd->BindString(1, name.c_str());
            checkCmd->BindString(2, owner.c_str());
            if(checkCmd->Step()) {
                LogDebug("Private name '" << name  << "' exists already for type "
                        << checkCmd->GetColumnInteger(0));
                return true;
            }
            return false;
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't check if name and label pair is present");
    }

    void DBCrypto::saveDBRow(const DBRow &row){
        Try {
            // Sqlite does not support partial index in our version,
            // so we do it by hand
            SqlConnection::DataCommandUniquePtr insertCommand =
                    m_connection->PrepareDataCommand(insert_main_cmd);
            insertCommand->BindString(1, row.name.c_str());
            insertCommand->BindString(2, row.ownerLabel.c_str());
            insertCommand->BindInteger(3, row.exportable);
            insertCommand->BindInteger(4, static_cast<int>(row.dataType));
            insertCommand->BindInteger(5, static_cast<int>(row.algorithmType));
            insertCommand->BindInteger(6, row.encryptionScheme);
            insertCommand->BindBlob(7, row.iv);
            insertCommand->BindInteger(8, row.dataSize);
            insertCommand->BindBlob(9, row.data);
            insertCommand->BindBlob(10, row.tag);

            insertCommand->Step();
            return;

        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't save DBRow");
    }

    DBRow DBCrypto::getRow(const SqlConnection::DataCommandUniquePtr &selectCommand) {
        DBRow row;
        row.name = selectCommand->GetColumnString(0);
        row.ownerLabel = selectCommand->GetColumnString(1);
        row.exportable = selectCommand->GetColumnInteger(2);
        row.dataType = static_cast<DBDataType>(selectCommand->GetColumnInteger(3));
        row.algorithmType = static_cast<DBCMAlgType>(selectCommand->GetColumnInteger(4));
        row.encryptionScheme = selectCommand->GetColumnInteger(5);
        row.iv = selectCommand->GetColumnBlob(6);
        row.dataSize = selectCommand->GetColumnInteger(7);
        row.data = selectCommand->GetColumnBlob(8);
        row.tag = selectCommand->GetColumnBlob(9);
        return row;
    }

    PermissionOptional DBCrypto::getPermissionRow(
        const Name &name,
        const Label &ownerLabel,
        const Label &accessorLabel) const
    {
        Try{
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(select_permission_cmd);
            selectCommand->BindString(1, accessorLabel.c_str());
            selectCommand->BindString(2, name.c_str());
            selectCommand->BindString(3, ownerLabel.c_str());

            if(selectCommand->Step())
                return PermissionOptional(toPermission(selectCommand->GetColumnString(0)));
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
        }
        return PermissionOptional();
    }

    DBCrypto::DBRowOptional DBCrypto::getDBRow(
        const Name &name,
        const Label &ownerLabel,
        DBDataType type)
    {
        return getDBRow(name, ownerLabel, type, type);
    }
    DBCrypto::DBRowOptional DBCrypto::getDBRow(
        const Name &name,
        const Label &ownerLabel,
        DBDataType typeRangeStart,
        DBDataType typeRangeStop)
    {
        Try {
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_row_by_name_label_type_cmd);
            selectCommand->BindString(1, name.c_str());
            selectCommand->BindString(2, ownerLabel.c_str());
            selectCommand->BindInteger(3, static_cast<int>(typeRangeStart));
            selectCommand->BindInteger(4, static_cast<int>(typeRangeStop));

            if(selectCommand->Step())
            {
                // extract data
                DBRow current_row = getRow(selectCommand);

                // all okay, proceed
                return DBRowOptional(current_row);
            } else {
                return DBRowOptional();
            }
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't get row of type <" <<
                static_cast<int>(typeRangeStart) << "," <<
                static_cast<int>(typeRangeStop)  << ">" <<
                " name " << name << " with owner label " << ownerLabel);
    }

    void DBCrypto::listNames(
        const Label &smackLabel,
        LabelNameVector& labelNameVector,
        DBDataType type)
    {
        listNames(smackLabel, labelNameVector, type, type);
    }

    void DBCrypto::listNames(
        const Label &smackLabel,
        LabelNameVector& labelNameVector,
        DBDataType typeRangeStart,
        DBDataType typeRangeStop)
    {
        Try{
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(select_key_type_cross_cmd);
            selectCommand->BindInteger(1, static_cast<int>(typeRangeStart));
            selectCommand->BindInteger(2, static_cast<int>(typeRangeStop));
            selectCommand->BindString(3, smackLabel.c_str());

            while(selectCommand->Step()) {
                Label ownerLabel = selectCommand->GetColumnString(0);
                Name name = selectCommand->GetColumnString(1);
                labelNameVector.push_back(std::make_pair(ownerLabel, name));
            }
            return;
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't list names of type <" <<
                static_cast<int>(typeRangeStart) << "," <<
                static_cast<int>(typeRangeStop)  << ">" <<
                " accessible to client label " << smackLabel);
    }

    bool DBCrypto::deleteDBRow(const Name &name, const Label &ownerLabel)
    {
        Try {
            if(countRows(name, ownerLabel) > 0)
            {
                SqlConnection::DataCommandUniquePtr deleteCommand =
                        m_connection->PrepareDataCommand(delete_name_cmd);
                deleteCommand->BindString(1, name.c_str());
                deleteCommand->BindString(2, ownerLabel.c_str());

                // Step() result code does not provide information whether
                // anything was removed.
                deleteCommand->Step();

                return true;
            }
            return false;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare delete statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute delete statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't delete DBRow for name " << name << " using client label " << ownerLabel);
    }

    int DBCrypto::countRows(const Name &name, const Label &ownerLabel) const
    {
        SqlConnection::DataCommandUniquePtr checkCmd =
                    m_connection->PrepareDataCommand(select_count_rows_cmd);
        checkCmd->BindString(1, name.c_str());
        checkCmd->BindString(2, ownerLabel.c_str());
        if(checkCmd->Step()) {
            return checkCmd->GetColumnInteger(0);
        } else {
            LogDebug("Row does not exist for name=" << name << "and label=" << ownerLabel);
            return 0;
        }
    }

    void DBCrypto::saveKey(
            const Label& label,
            const RawBuffer &key)
    {
        Try {
            SqlConnection::DataCommandUniquePtr insertCommand =
                    m_connection->PrepareDataCommand(insert_key_cmd);
            insertCommand->BindString(1, label.c_str());
            insertCommand->BindBlob(2, key);
            insertCommand->Step();
            return;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert key statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't save key for label " << label);
    }

    DBCrypto::RawBufferOptional DBCrypto::getKey(const Label& label)
    {
        Try {
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_key_cmd);
            selectCommand->BindString(1, label.c_str());

            if (selectCommand->Step()) {
                return RawBufferOptional(
                        selectCommand->GetColumnBlob(0));
            } else {
                return RawBufferOptional();
            }

        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert key statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't get key for label " << label);
    }

    void DBCrypto::deleteKey(const Label& label) {
        Try {
            Transaction transaction(this);

            SqlConnection::DataCommandUniquePtr deleteCommand =
                    m_connection->PrepareDataCommand(delete_key_cmd);
            deleteCommand->BindString(1, label.c_str());
            deleteCommand->Step();

            SqlConnection::DataCommandUniquePtr deleteData =
                m_connection->PrepareDataCommand(delete_data_with_key_cmd);
            deleteData->BindString(1, label.c_str());
            deleteData->Step();

            transaction.commit();
            return;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert key statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't delete key for label " << label);
    }

    int DBCrypto::setPermission(
            const Name &name,
            const Label& ownerLabel,
            const Label& accessorLabel,
            const Permission permissions)
    {
        Try {
            if(permissions == Permission::NONE)
            {
                // clear access rights
                SqlConnection::DataCommandUniquePtr deletePermissionCommand =
                    m_connection->PrepareDataCommand(delete_permission_cmd);
                deletePermissionCommand->BindString(1, name.c_str());
                deletePermissionCommand->BindString(2, ownerLabel.c_str());
                deletePermissionCommand->BindString(3, accessorLabel.c_str());
                deletePermissionCommand->Step();
            }
            else
            {
                // add new rights
                SqlConnection::DataCommandUniquePtr setPermissionCommand =
                    m_connection->PrepareDataCommand(set_permission_name_cmd);
                setPermissionCommand->BindString(1, accessorLabel.c_str());
                setPermissionCommand->BindString(2, toDBPermission(permissions));
                setPermissionCommand->BindString(3, name.c_str());
                setPermissionCommand->BindString(4, ownerLabel.c_str());
                setPermissionCommand->Step();
            }
            return CKM_API_SUCCESS;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare set statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute set statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't set permissions for name " << name );
    }

} // namespace CKM

#pragma GCC diagnostic pop
