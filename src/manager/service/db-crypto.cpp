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

// CKM_TABLE (alias TEXT, label TEXT, restricted INT, exportable INT, dataType INT,
//            algorithmType INT, encryptionScheme INT, iv BLOB, dataSize INT, data BLOB)

    const char *db_create_main_cmd =
            "CREATE TABLE CKM_TABLE("
            "   alias TEXT NOT NULL,"
            "   label TEXT NOT NULL,"
            "   exportable INTEGER NOT NULL,"
            "   dataType INTEGER NOT NULL,"
            "   algorithmType INTEGER NOT NULL,"
            "   encryptionScheme INTEGER NOT NULL,"
            "   iv BLOB NOT NULL,"
            "   dataSize INTEGER NOT NULL,"
            "   data BLOB NOT NULL,"
            "   tag BLOB NOT NULL,"
            "   PRIMARY KEY(alias)"
            "); CREATE INDEX alias_idx ON CKM_TABLE(alias);";

    const char *insert_main_cmd =
            "INSERT INTO CKM_TABLE("
            //      1   2       3
            "   alias, label, exportable,"
            //      4           5           6
            "   dataType, algorithmType, encryptionScheme,"
            //  7       8       9    10
            "   iv, dataSize, data, tag) "
            "VALUES("
            "   ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    const char *select_alias_cmd =
            //                                   1              2
            "SELECT * FROM CKM_TABLE WHERE alias=? AND dataType=?; ";

    const char *select_check_alias_cmd =
            //                                          1
            "SELECT dataType FROM CKM_TABLE WHERE alias=?;";

    const char *select_check_global_alias_cmd =
            //                                       1
            "SELECT label FROM CKM_TABLE WHERE alias=?;";

    const char *select_key_alias_cmd =
            //                                   1
            "SELECT * FROM CKM_TABLE WHERE alias=?"
            //                     2     3
            " AND dataType BETWEEN ? AND ?;";

    const char *delete_alias_cmd =
            //                                 1
            "DELETE FROM CKM_TABLE WHERE alias=?;";

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


// PERMISSION_TABLE (label TEXT, label TEXT, access_flags TEXT)

    const char *db_create_permission_cmd =
            "CREATE TABLE PERMISSION_TABLE("
            "   alias TEXT NOT NULL,"
            "   label TEXT NOT NULL,"
            "   accessFlags TEXT NOT NULL,"
            "   FOREIGN KEY(alias) REFERENCES CKM_TABLE(alias) ON DELETE CASCADE,"
            "   PRIMARY KEY(alias, label)"
            "); CREATE INDEX alias_label_idx ON PERMISSION_TABLE(alias, label);";

    const char *set_permission_alias_cmd =
            "REPLACE INTO PERMISSION_TABLE(alias, label, accessFlags) VALUES (?, ?, ?);";

    const char *select_permission_cmd =
            //                                                    1           2
            "SELECT accessFlags FROM PERMISSION_TABLE WHERE alias=? AND label=?;";

    const char *delete_permission_cmd =
            //                                        1           2
            "DELETE FROM PERMISSION_TABLE WHERE alias=? AND label=?;";


// CKM_TABLE x PERMISSION_TABLE

    const char *select_type_cross_cmd =
            //                                                                                                        1              2             3
            "SELECT C.alias FROM CKM_TABLE AS C LEFT JOIN PERMISSION_TABLE AS P ON C.alias = P.alias WHERE C.dataType=? AND (C.label=? OR (P.label=? AND P.accessFlags IS NOT NULL)) GROUP BY C.alias;";

    const char *select_key_type_cross_cmd =
            //                                                                                                       1                 2              3             4
            "SELECT C.alias FROM CKM_TABLE AS C LEFT JOIN PERMISSION_TABLE AS P ON C.alias=P.alias WHERE C.dataType>=? AND C.dataType<=? AND (C.label=? OR (P.label=? AND P.accessFlags IS NOT NULL)) GROUP BY C.alias;";
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

    std::string DBCrypto::getLabelForAlias(const std::string& alias) const {
        SqlConnection::DataCommandUniquePtr checkCmd =
                m_connection->PrepareDataCommand(select_check_global_alias_cmd);
        checkCmd->BindString(1, alias.c_str());
        if(checkCmd->Step()) {
            return checkCmd->GetColumnString(0);
        } else
            return std::string();
    }
    bool DBCrypto::checkGlobalAliasExist(const std::string& alias) const {
        std::string label = this->getLabelForAlias(alias);
        if(label.empty() == false) {
            LogDebug("Global alias '" << alias  << "' exists already for label " << label);
            return true;
        } else
            return false;
    }

    bool DBCrypto::checkAliasExist(const std::string& alias) const {
        SqlConnection::DataCommandUniquePtr checkCmd =
                m_connection->PrepareDataCommand(select_check_alias_cmd);
        checkCmd->BindString(1, alias.c_str());
        if(checkCmd->Step()) {
            LogDebug("Private alias '" << alias  << "' exists already for type "
                    << checkCmd->GetColumnInteger(0));
            return true;
        } else
            return false;
    }

    void DBCrypto::saveDBRow(const DBRow &row){
        Try {

            //Sqlite does not support partial index in our version,
            //so we do it by hand
            Transaction transaction(this);
            if(checkAliasExist(row.alias)) {
                ThrowMsg(DBCrypto::Exception::AliasExists,
                        "Alias exists for alias: " << row.alias);
            }

            SqlConnection::DataCommandUniquePtr insertCommand =
                    m_connection->PrepareDataCommand(insert_main_cmd);
            insertCommand->BindString(1, row.alias.c_str());
            insertCommand->BindString(2, row.smackLabel.c_str());
            insertCommand->BindInteger(3, row.exportable);
            insertCommand->BindInteger(4, static_cast<int>(row.dataType));
            insertCommand->BindInteger(5, static_cast<int>(row.algorithmType));
            insertCommand->BindInteger(6, row.encryptionScheme);
            insertCommand->BindBlob(7, row.iv);
            insertCommand->BindInteger(8, row.dataSize);
            insertCommand->BindBlob(9, row.data);
            insertCommand->BindBlob(10, row.tag);

            insertCommand->Step();
            transaction.commit();
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
        row.alias = selectCommand->GetColumnString(0);
        row.smackLabel = selectCommand->GetColumnString(1);
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

    std::string DBCrypto::getPermissionsForAliasAndLabel(const Alias &alias, const std::string &label) const
    {
        Try{
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(select_permission_cmd);
            selectCommand->BindString(1, alias.c_str());
            selectCommand->BindString(2, label.c_str());

            if(selectCommand->Step())
                return selectCommand->GetColumnString(0);

            return std::string();
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
        }
        return std::string();
    }


    bool    DBCrypto::rowAccessControlCheck(const Alias &alias,
                                            const std::string &owner_label,
                                            const std::string &clnt_label,
                                            DBCrypto::DBOperationType access_type) const
    {
        // owner of the entry have all the permissions by default
        // check if requesting client is the entry owner - if so, exit (permission granted)
        if(owner_label == clnt_label)
            return true;

        // perform permissions DB query
        std::string permission_string = this->getPermissionsForAliasAndLabel(alias, clnt_label);

        // check if requested operation is in the permission string
        LogDebug("pair <" << alias << "," << clnt_label << "> permission rights: \"" << permission_string << "\"");
        if(permission_string.find(access_type) != std::string::npos)
            return true;

        return false;
    }
    bool    DBCrypto::rowAccessControlCheck(const DBRow & input_row,
                                            const std::string &clnt_label,
                                            DBCrypto::DBOperationType access_type) const
    {
        return this->rowAccessControlCheck(input_row.alias, input_row.smackLabel, clnt_label, access_type);
    }


    DBCrypto::DBRowOptional DBCrypto::getDBRow(
        const Alias &alias,
        const std::string &clnt_label,
        DBDataType type)
    {
        Try {
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_alias_cmd);
            selectCommand->BindString(1, alias.c_str());
            selectCommand->BindInteger(2, static_cast<int>(type));

            if(selectCommand->Step())
            {
                // extract data
                DBRow current_row = getRow(selectCommand);

                // check access rights here
                if( ! this->rowAccessControlCheck(current_row, clnt_label, DBCrypto::DB_OPERATION_READ) )
                    ThrowMsg(Exception::PermissionDenied, "Not enough permissions to perform requested operation");

                // finalize DB operations
                transaction.commit();

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
                "Couldn't get row for type " << static_cast<int>(type) <<
                " alias " << alias << " using client label " << clnt_label);
    }

    DBCrypto::DBRowOptional DBCrypto::getKeyDBRow(
        const Alias &alias,
        const std::string &clnt_label)
    {
        Try{
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_key_alias_cmd);
            selectCommand->BindString(1, alias.c_str());
            selectCommand->BindInteger(2, static_cast<int>(DBDataType::DB_KEY_FIRST));
            selectCommand->BindInteger(3, static_cast<int>(DBDataType::DB_KEY_LAST));

            if(selectCommand->Step())
            {
                // extract data
                DBRow current_row = getRow(selectCommand);

                // check access rights here
                if( ! this->rowAccessControlCheck(current_row, clnt_label, DBCrypto::DB_OPERATION_READ) )
                    ThrowMsg(Exception::PermissionDenied, "Not enough permissions to perform requested operation");

                // finalize DB operations
                transaction.commit();

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
                "Couldn't get Key for alias " << alias
                << " using client label " << clnt_label);
    }

    void DBCrypto::getSingleType(
            const std::string &clnt_label,
            DBDataType type,
            AliasVector& aliases) const
    {
        Try{
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(select_type_cross_cmd);
            selectCommand->BindInteger(1, static_cast<int>(type));
            selectCommand->BindString(2, clnt_label.c_str());
            selectCommand->BindString(3, clnt_label.c_str());

            while(selectCommand->Step()) {
                Alias alias;
                alias = selectCommand->GetColumnString(0);
                aliases.push_back(alias);
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
                "Couldn't get type " << static_cast<int>(type));
    }

    void DBCrypto::getAliases(
        const std::string &clnt_label,
        DBDataType type,
        AliasVector& aliases)
    {
        getSingleType(clnt_label, type, aliases);
    }


    void DBCrypto::getKeyAliases(const std::string &clnt_label, AliasVector &aliases)
    {
        Try{
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(select_key_type_cross_cmd);
            selectCommand->BindInteger(1, static_cast<int>(DBDataType::DB_KEY_FIRST));
            selectCommand->BindInteger(2, static_cast<int>(DBDataType::DB_KEY_LAST));
            selectCommand->BindString(3, clnt_label.c_str());
            selectCommand->BindString(4, clnt_label.c_str());

            while(selectCommand->Step()) {
                Alias alias;
                alias = selectCommand->GetColumnString(0);
                aliases.push_back(alias);
            }
            transaction.commit();
            return;
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError, "Couldn't get key aliases");
    }

    bool DBCrypto::deleteDBRow(const Alias &alias, const std::string &clnt_label)
    {
        Try {
            Transaction transaction(this);

            std::string owner_label = getLabelForAlias(alias);
            if( ! owner_label.empty() )
            {
                // check access rights here
                if( ! this->rowAccessControlCheck(alias, owner_label, clnt_label, DBCrypto::DB_OPERATION_REMOVE) )
                    ThrowMsg(Exception::PermissionDenied, "Not enough permissions to perform requested remove operation");

                // if here, access right is granted - proceed with removal
                // note: PERMISSION_TABLE entry will be deleted automatically by SQL (cascade relation between tables)
                SqlConnection::DataCommandUniquePtr deleteCommand =
                        m_connection->PrepareDataCommand(delete_alias_cmd);
                deleteCommand->BindString(1, alias.c_str());
                deleteCommand->Step();

                transaction.commit();
                return true;
            }
            else
            {
                LogError("Error: no such alias: " << alias);
                return false;
            }
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare delete statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute delete statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't delete DBRow for alias " << alias << " using client label " << clnt_label);
    }

    void DBCrypto::saveKey(
            const std::string& label,
            const RawBuffer &key)
    {
        Try {
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr insertCommand =
                    m_connection->PrepareDataCommand(insert_key_cmd);
            insertCommand->BindString(1, label.c_str());
            insertCommand->BindBlob(2, key);
            insertCommand->Step();
            transaction.commit();
            return;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert key statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't save key for label " << label);
    }

    DBCrypto::RawBufferOptional DBCrypto::getKey(
            const std::string& label)
    {
        Try {
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_key_cmd);
            selectCommand->BindString(1, label.c_str());

            if (selectCommand->Step()) {
                transaction.commit();
                return RawBufferOptional(
                        selectCommand->GetColumnBlob(0));
            } else {
                transaction.commit();
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

    void DBCrypto::deleteKey(const std::string& label) {
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


    int DBCrypto::setAccessRights(  const std::string& clnt_label,
                                    const Alias& alias,
                                    const std::string& accessor_label,
                                    const AccessRight value_to_set)
    {
        Try {
            Transaction transaction(this);

            // check if label is present
            std::string owner_label = getLabelForAlias(alias);
            if( ! owner_label.empty() )
            {
                // owner can not add permissions to itself
                if(owner_label.compare(accessor_label) == 0)
                    ThrowMsg(Exception::InvalidArgs, "Invalid accessor label: equal to owner label");

                // check access rights here - only owner can modify permissions
                if(owner_label != clnt_label)
                    ThrowMsg(Exception::PermissionDenied, "Not enough permissions to perform requested write operation");

                // if here, access right is granted - proceed to set permissions
                SqlConnection::DataCommandUniquePtr setPermissionCommand =
                        m_connection->PrepareDataCommand(set_permission_alias_cmd);
                setPermissionCommand->BindString(1, alias.c_str());
                setPermissionCommand->BindString(2, accessor_label.c_str());
                setPermissionCommand->BindString(3, toDBAccessRight(value_to_set));
                setPermissionCommand->Step();
                transaction.commit();
                return CKM_API_SUCCESS;
            }
            else
            {
                LogError("Error: no such alias: " << alias);
                return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
            }
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare set statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute set statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't set permissions for alias " << alias << " using client label " << clnt_label);
    }

    int DBCrypto::clearAccessRights(const std::string& clnt_label,
                                    const Alias& alias,
                                    const std::string& accessor_label)
    {
        Try {
            Transaction transaction(this);

            std::string owner_label = getLabelForAlias(alias);
            if( ! owner_label.empty() )
            {
                // check access rights here - only owner can modify permissions
                if(owner_label != clnt_label)
                    ThrowMsg(Exception::PermissionDenied, "Not enough permissions to perform requested write operation");

                // check if permission for <label, accessor_label> is defined - otherwise nothing to drop
                if( this->getPermissionsForAliasAndLabel(alias, accessor_label).empty() )
                    ThrowMsg(Exception::InvalidArgs, "Permission not found");

                // if here, access right is granted - proceed to delete permissions
                SqlConnection::DataCommandUniquePtr deletePermissionCommand =
                        m_connection->PrepareDataCommand(delete_permission_cmd);
                deletePermissionCommand->BindString(1, alias.c_str());
                deletePermissionCommand->BindString(2, accessor_label.c_str());
                deletePermissionCommand->Step();
                transaction.commit();
                return CKM_API_SUCCESS;
            }
            else
            {
                LogError("Error: no such alias: " << alias);
                return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
            }
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare delete statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute delete statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't delete permissions for alias " << alias << " using client label " << clnt_label);
    }

} // CKM

#pragma GCC diagnostic pop
