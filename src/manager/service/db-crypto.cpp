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

    const char *select_name_cmd =
            "SELECT * FROM CKM_TABLE WHERE name=?001 AND label=?002 AND dataType=?003; ";

    const char *select_name_cmd_join =
            "SELECT * FROM CKM_TABLE WHERE name=?001 AND label=?002 AND dataType=?004 AND "
            " idx in (SELECT idx FROM PERMISSION_TABLE WHERE label = ?003); ";

    const char *select_check_name_cmd =
            "SELECT dataType FROM CKM_TABLE WHERE name=?001 AND label=?002;";

    const char *select_label_global_name_cmd =
            "SELECT count(*) FROM CKM_TABLE WHERE name=?001 AND label=?002; ";

//    const char *select_label_index_global_name_cmd =
//            //                                           1
//            "SELECT label, idx FROM CKM_TABLE WHERE name=?;";

    const char *select_key_name_cmd =
            "SELECT * FROM CKM_TABLE WHERE name=?001 AND label=?002"
            " AND dataType BETWEEN ?003 AND ?004;";

    const char *select_key_name_cmd_join =
            "SELECT * FROM CKM_TABLE WHERE name=?001 AND label=?002"
            " AND dataType BETWEEN ?004 AND ?005 " 
            " AND idx in (SELECT idx FROM PERMISSION_TABLE WHERE label = ?003);";

    const char *select_count_rows_cmd =
            "SELECT COUNT(idx) FROM CKM_TABLE WHERE name=?001 AND label=?002;";

    const char *delete_name_cmd =
            "DELETE FROM CKM_TABLE WHERE name=?001 AND label=?002;";

    const char *delete_name_cmd_join =
            "DELETE FROM CKM_TABLE WHERE name=?001 AND label=?002 AND "
            " idx in (SELECT idx FROM PERMISSION_TABLE WHERE label=?003);";


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

    const char *select_type_cross_cmd =
            "SELECT C.label, C.name FROM CKM_TABLE AS C LEFT JOIN PERMISSION_TABLE AS P ON C.idx = P.idx WHERE "
            "C.dataType=?001 AND (C.label=?002 OR (P.label=?002 AND P.accessFlags IS NOT NULL)) GROUP BY C.name;";

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

//    void DBCrypto::getLabelForName(const Name &name, Label & label) const {
//        SqlConnection::DataCommandUniquePtr checkCmd =
//                m_connection->PrepareDataCommand(select_label_global_name_cmd);
//        checkCmd->BindString(1, name.c_str());
//        if(checkCmd->Step()) {
//            label = checkCmd->GetColumnString(0);
//        } else
//            label.clear();
//    }

//    void DBCrypto::getLabelForName(const Name &name, Label & label, int & index) const
//    {
//        SqlConnection::DataCommandUniquePtr checkCmd =
//                m_connection->PrepareDataCommand(select_label_index_global_name_cmd);
//        checkCmd->BindString(1, name.c_str());
//        if(checkCmd->Step()) {
//            label = checkCmd->GetColumnString(0);
//            index = checkCmd->GetColumnInteger(1);
//        }
//        else
//        {
//            label.clear();
//            index = -1;
//        }
//    }

    bool DBCrypto::checkGlobalNameExist(const Name &name, const Label &ownerLabel) const {
        SqlConnection::DataCommandUniquePtr checkCmd =
                m_connection->PrepareDataCommand(select_label_global_name_cmd);
        checkCmd->BindString(1, name.c_str());
        checkCmd->BindString(2, ownerLabel.c_str());
        if(checkCmd->Step())
            return checkCmd->GetColumnInteger(0)?true:false;
        return false;
    }

    bool DBCrypto::checkNameExist(const Name &name, const Label &owner) const {
        SqlConnection::DataCommandUniquePtr checkCmd =
                m_connection->PrepareDataCommand(select_check_name_cmd);
        checkCmd->BindString(1, name.c_str());
        checkCmd->BindString(2, owner.c_str());
        if(checkCmd->Step()) {
            LogDebug("Private name '" << name  << "' exists already for type "
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
            if(checkNameExist(row.name, row.smackLabel)) {
                ThrowMsg(DBCrypto::Exception::NameExists,
                        "Name exists for name: " << row.name);
            }

            SqlConnection::DataCommandUniquePtr insertCommand =
                    m_connection->PrepareDataCommand(insert_main_cmd);
            insertCommand->BindString(1, row.name.c_str());
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
        row.name = selectCommand->GetColumnString(0);
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

    std::string DBCrypto::getPermissions(const Name &name, const Label &ownerLabel, const Label &smackLabel) const
    {
        Try{
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(select_permission_cmd);
            selectCommand->BindString(1, smackLabel.c_str());
            selectCommand->BindString(2, name.c_str());
            selectCommand->BindString(3, ownerLabel.c_str());

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

    DBCrypto::DBRowOptional DBCrypto::getDBRow(
        const Name &name,
        const Label &ownerLabel,
        const Label &smackLabel,
        DBDataType type)
    {
        if (ownerLabel == smackLabel)
            return getDBRowSimple(name, ownerLabel, type);
        return getDBRowJoin(name, ownerLabel, smackLabel, type);
    }

    DBCrypto::DBRowOptional DBCrypto::getDBRowSimple(
        const Name &name,
        const Label &owner,
        DBDataType type)
    {
        Try {
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_name_cmd);
            selectCommand->BindString(1, name.c_str());
            selectCommand->BindString(2, owner.c_str());
            selectCommand->BindInteger(3, static_cast<int>(type));

            if(selectCommand->Step())
            {
                // extract data
                DBRow current_row = getRow(selectCommand);

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
                " name " << name << " using client label " << owner);
    }

    DBCrypto::DBRowOptional DBCrypto::getDBRowJoin(
        const Name &name,
        const Label &ownerLabel,
        const Label &smackLabel,
        DBDataType type)
    {
        Try {
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_name_cmd_join);
            selectCommand->BindString(1, name.c_str());
            selectCommand->BindString(2, ownerLabel.c_str());
            selectCommand->BindString(3, smackLabel.c_str());
            selectCommand->BindInteger(4, static_cast<int>(type));

            if(selectCommand->Step())
            {
                // extract data
                DBRow current_row = getRow(selectCommand);

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
                " name " << name << " using client label " << smackLabel);
    }

    DBCrypto::DBRowOptional DBCrypto::getKeyDBRow(
        const Name &name,
        const Label &ownerLabel,
        const Label &smackLabel)
    {
        if (ownerLabel == smackLabel)
            return getKeyDBRowSimple(name, ownerLabel);
        else
            return getKeyDBRowJoin(name, ownerLabel, smackLabel);
    }

    DBCrypto::DBRowOptional DBCrypto::getKeyDBRowSimple(
        const Name &name,
        const Label &ownerLabel)
    {
        Try{
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_key_name_cmd);
            selectCommand->BindString(1, name.c_str());
            selectCommand->BindString(2, ownerLabel.c_str());
            selectCommand->BindInteger(3, static_cast<int>(DBDataType::DB_KEY_FIRST));
            selectCommand->BindInteger(4, static_cast<int>(DBDataType::DB_KEY_LAST));

            if(selectCommand->Step())
            {
                // extract data
                DBRow current_row = getRow(selectCommand);

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
                "Couldn't get Key for name " << name
                << " using client label " << ownerLabel);
    }

    DBCrypto::DBRowOptional DBCrypto::getKeyDBRowJoin(
        const Name &name,
        const Label &ownerLabel,
        const Label &smackLabel)
    {
        Try{
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(select_key_name_cmd_join);
            selectCommand->BindString(1, name.c_str());
            selectCommand->BindString(2, ownerLabel.c_str());
            selectCommand->BindString(3, smackLabel.c_str());
            selectCommand->BindInteger(4, static_cast<int>(DBDataType::DB_KEY_FIRST));
            selectCommand->BindInteger(5, static_cast<int>(DBDataType::DB_KEY_LAST));

            if(selectCommand->Step())
            {
                // extract data
                DBRow current_row = getRow(selectCommand);

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
                "Couldn't get Key for name " << name
                << " using client label " << smackLabel);
    }

    void DBCrypto::getSingleType(
            const Label &clnt_label,
            DBDataType type,
            LabelNameVector& labelNameVector) const
    {
        Try{
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(select_type_cross_cmd);
            selectCommand->BindInteger(1, static_cast<int>(type));
            selectCommand->BindString(2, clnt_label.c_str());

            while(selectCommand->Step()) {
                Label label = selectCommand->GetColumnString(0);
                Name name = selectCommand->GetColumnString(1);
                labelNameVector.push_back(std::make_pair(label, name));
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

    void DBCrypto::getNames(
        const Label &clnt_label,
        DBDataType type,
        LabelNameVector& labelNameVector)
    {
        getSingleType(clnt_label, type, labelNameVector);
    }


    void DBCrypto::getKeyNames(const Label &clnt_label, LabelNameVector &labelNameVector)
    {
        Try{
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(select_key_type_cross_cmd);
            selectCommand->BindInteger(1, static_cast<int>(DBDataType::DB_KEY_FIRST));
            selectCommand->BindInteger(2, static_cast<int>(DBDataType::DB_KEY_LAST));
            selectCommand->BindString(3, clnt_label.c_str());

            while(selectCommand->Step()) {
                Label label = selectCommand->GetColumnString(0);
                Name name = selectCommand->GetColumnString(1);
                labelNameVector.push_back(std::make_pair(label, name));
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
        ThrowMsg(DBCrypto::Exception::InternalError, "Couldn't get key names");
    }

    bool DBCrypto::deleteDBRow(const Name &name, const Label &ownerLabel, const Label &credLabel) {
        if (ownerLabel == credLabel)
            return deleteDBRowSimple(name, ownerLabel);
        return deleteDBRowJoin(name, ownerLabel, credLabel);
    }

    bool DBCrypto::deleteDBRowSimple(const Name &name, const Label &ownerLabel)
    {
        Try {
            Transaction transaction(this);

            if(countRows(name, ownerLabel) > 0)
            {
                SqlConnection::DataCommandUniquePtr deleteCommand =
                        m_connection->PrepareDataCommand(delete_name_cmd);
                deleteCommand->BindString(1, name.c_str());
                deleteCommand->BindString(2, ownerLabel.c_str());

                // Step() result code does not provide information whether
                // anything was removed.
                deleteCommand->Step();
                transaction.commit();

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

    bool DBCrypto::deleteDBRowJoin(const Name &name, const Label &ownerLabel, const Label &smackLabel)
    {
        Try {
            Transaction transaction(this);

            if (!checkNameExist(name, ownerLabel))
                return false;

            std::string permissions = DBCrypto::getPermissions(name, ownerLabel, smackLabel);
            if(permissions.empty() == false)
            {
                // entry present, check if for reading or read/remove
                if(permissions.find(toDBAccessRight(AccessRight::AR_READ_REMOVE)) == std::string::npos)
                    ThrowMsg(DBCrypto::Exception::PermissionDenied, "Client " << smackLabel << " can only read " <<
                             ownerLabel << CKM::LABEL_NAME_SEPARATOR << name << ", remove forbidden");

                SqlConnection::DataCommandUniquePtr deleteCommand =
                    m_connection->PrepareDataCommand(delete_name_cmd_join);
                deleteCommand->BindString(1, name.c_str());
                deleteCommand->BindString(2, ownerLabel.c_str());
                deleteCommand->BindString(3, smackLabel.c_str());

                // Step() result code does not provide information whether
                // anything was removed.
                deleteCommand->Step();
                transaction.commit();

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

    int DBCrypto::countRows(const Name &name, const Label &ownerLabel) {
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

    DBCrypto::RawBufferOptional DBCrypto::getKey(const Label& label)
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

    int DBCrypto::setAccessRights(
            const Name &name,
            const Label& ownerLabel,
            const Label& accessorLabel,
            const AccessRight accessRights)
    {
        Try {
            Transaction transaction(this);

            // owner can not add permissions to itself
            if(ownerLabel.compare(accessorLabel) == 0)
                return CKM_API_ERROR_INPUT_PARAM;

            if (!checkNameExist(name, ownerLabel))
                return CKM_API_ERROR_DB_ALIAS_UNKNOWN;

            SqlConnection::DataCommandUniquePtr setPermissionCommand =
                m_connection->PrepareDataCommand(set_permission_name_cmd);
            setPermissionCommand->BindString(1, accessorLabel.c_str());
            setPermissionCommand->BindString(2, toDBAccessRight(accessRights));
            setPermissionCommand->BindString(3, name.c_str());
            setPermissionCommand->BindString(4, ownerLabel.c_str());
            setPermissionCommand->Step();
            transaction.commit();
            return CKM_API_SUCCESS;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare set statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute set statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't set permissions for name " << name );
    }

    int DBCrypto::clearAccessRights(
            const Name &name,
            const Label &ownerLabel,
            const Label &accessorLabel)
    {
        Try {
            Transaction transaction(this);

            // owner can not add permissions to itself
            if(ownerLabel.compare(accessorLabel) == 0)
                return CKM_API_ERROR_INPUT_PARAM;

            // check if CKM entry present
            if (!checkNameExist(name, ownerLabel)) {
                transaction.commit();
                return CKM_API_ERROR_DB_ALIAS_UNKNOWN;
            }

            // check if permission entry present
            if( DBCrypto::getPermissions(name, ownerLabel, accessorLabel).empty() )
                return CKM_API_ERROR_INPUT_PARAM;

            SqlConnection::DataCommandUniquePtr deletePermissionCommand =
                m_connection->PrepareDataCommand(delete_permission_cmd);
            deletePermissionCommand->BindString(1, name.c_str());
            deletePermissionCommand->BindString(2, ownerLabel.c_str());
            deletePermissionCommand->BindString(3, accessorLabel.c_str());
            deletePermissionCommand->Step();
            transaction.commit();
            return CKM_API_SUCCESS;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare delete statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute delete statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't delete permissions for name " << name);
    }

} // namespace CKM

#pragma GCC diagnostic pop
