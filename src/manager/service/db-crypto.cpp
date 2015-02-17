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
    const char *TABLE_NAME          = "NAME_TABLE";
    const char *TABLE_OBJECT        = "OBJECT_TABLE";
    const char *TABLE_KEY           = "KEY_TABLE";
    const char *TABLE_PERMISSION    = "PERMISSION_TABLE";

    const char *DB_CMD_NAME_CREATE =
            "CREATE TABLE NAME_TABLE("
            "   name TEXT NOT NULL,"
            "   label TEXT NOT NULL,"
            "   idx INTEGER PRIMARY KEY AUTOINCREMENT,"
            "   UNIQUE(name, label)"
            "); CREATE INDEX name_index_idx ON NAME_TABLE(idx);";

    const char *DB_CMD_NAME_INSERT =
            "INSERT INTO NAME_TABLE("
            "   name, label) "
            "   VALUES(?101, ?102);";

    // any idea how to do it using constexpr ?
    #define DB_CMD_NAME_LOOKUP_IDX \
            "(SELECT idx FROM NAME_TABLE WHERE name=?101 and label=?102)"

    const char *DB_CMD_NAME_COUNT_ROWS =
            "SELECT COUNT(idx) FROM NAME_TABLE WHERE name=?101 AND label=?102;";

    const char *DB_CMD_NAME_DELETE =
            "DELETE FROM NAME_TABLE WHERE name=?101 AND label=?102;";

    const char *DB_CMD_NAME_DELETE_BY_LABEL =
            "DELETE FROM NAME_TABLE WHERE label=?102;";

    const char *DB_CMD_OBJECT_CREATE =
            "CREATE TABLE OBJECT_TABLE("
            "   exportable INTEGER NOT NULL,"
            "   dataType INTEGER NOT NULL,"
            "   algorithmType INTEGER NOT NULL,"
            "   encryptionScheme INTEGER NOT NULL,"
            "   iv BLOB NOT NULL,"
            "   dataSize INTEGER NOT NULL,"
            "   data BLOB NOT NULL,"
            "   tag BLOB NOT NULL,"
            "   idx INTEGER NOT NULL,"
            "   FOREIGN KEY(idx) REFERENCES NAME_TABLE(idx) ON DELETE CASCADE,"
            "   PRIMARY KEY(idx, dataType)"
            ");"; // TODO: index and performance tests

    const char *DB_CMD_OBJECT_INSERT =
            "INSERT INTO OBJECT_TABLE("
            "   exportable, dataType,"
            "   algorithmType, encryptionScheme,"
            "   iv, dataSize, data, tag, idx) "
            "   VALUES(?001, ?002, ?003, ?004, ?005, "
            "          ?006, ?007, ?008, " DB_CMD_NAME_LOOKUP_IDX ");";

    const char *DB_CMD_OBJECT_SELECT_BY_NAME_AND_LABEL =
            "SELECT * FROM OBJECT_TABLE WHERE "
            " (dataType BETWEEN ?001 AND ?002) AND "
            " idx=" DB_CMD_NAME_LOOKUP_IDX ";";


    const char *DB_CMD_KEY_CREATE =
            "CREATE TABLE KEY_TABLE("
            "   label TEXT PRIMARY KEY,"
            "   key BLOB NOT NULL"
            ");";

    const char *DB_CMD_KEY_INSERT =
            "INSERT INTO KEY_TABLE(label, key) VALUES (?, ?);";
    const char *DB_CMD_KEY_SELECT =
            "SELECT key FROM KEY_TABLE WHERE label=?;";
    const char *DB_CMD_KEY_DELETE =
            "DELETE FROM KEY_TABLE WHERE label=?";


    const char *DB_CMD_PERMISSION_CREATE =
            "CREATE TABLE PERMISSION_TABLE("
            "   label TEXT NOT NULL,"
            "   accessFlags TEXT NOT NULL,"
            "   idx INTEGER NOT NULL,"
            "   FOREIGN KEY(idx) REFERENCES NAME_TABLE(idx) ON DELETE CASCADE,"
            "   PRIMARY KEY(label, idx)"
            "); CREATE INDEX perm_index_idx ON PERMISSION_TABLE(idx);"; // based on ANALYZE and performance test result

    const char *DB_CMD_PERMISSION_SET =
            "REPLACE INTO PERMISSION_TABLE(label, accessFlags, idx) "
            " VALUES (?001, ?002, " DB_CMD_NAME_LOOKUP_IDX ");";

    const char *DB_CMD_PERMISSION_SELECT =
            "SELECT accessFlags FROM PERMISSION_TABLE WHERE label=?001 AND "
            " idx=" DB_CMD_NAME_LOOKUP_IDX ";";

    const char *DB_CMD_PERMISSION_DELETE =
            "DELETE FROM PERMISSION_TABLE WHERE label=?001 AND "
            " idx=" DB_CMD_NAME_LOOKUP_IDX ";";


    /*
     * GROUP BY is necessary because of the following case:
     * -There are several permissions to L1, N1 (label, name) from other accessors. When listing
     *  objects accessible by L1 the query will produce one result (L1, N1) for each allowed
     *  accessor but GROUP BY will reduce them to one so L1 will have (L1, N1) on its list only once
     */
    const char *DB_CMD_NAME_SELECT_BY_TYPE_AND_PERMISSION =
            "SELECT N.label, N.name FROM NAME_TABLE AS N "
            " JOIN OBJECT_TABLE AS O ON O.idx=N.idx "
            " LEFT JOIN PERMISSION_TABLE AS P ON P.idx=N.idx "
            " WHERE O.dataType>=?001 AND O.dataType<=?002 AND "
            " ((N.label=?003) OR (P.label=?003 AND P.accessFlags IS NOT NULL)) GROUP BY N.idx;";
}

namespace CKM {
using namespace DB;
    DBCrypto::DBCrypto(const std::string& path, const RawBuffer &rawPass)
    {
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
            m_inUserTransaction(other.m_inUserTransaction)
    {
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
        if(!m_connection->CheckTableExist(TABLE_NAME)) {
            createTable(DB_CMD_NAME_CREATE, TABLE_NAME);
        }
        if(!m_connection->CheckTableExist(TABLE_OBJECT)) {
            createTable(DB_CMD_OBJECT_CREATE, TABLE_OBJECT);
        }
        if(!m_connection->CheckTableExist(TABLE_KEY)) {
            createTable(DB_CMD_KEY_CREATE, TABLE_KEY);
        }
        if(!m_connection->CheckTableExist(TABLE_PERMISSION)) {
            createTable(DB_CMD_PERMISSION_CREATE, TABLE_PERMISSION);
        }
        transaction.commit();
    }

    bool DBCrypto::isNameLabelPresent(const Name &name, const Label &owner) const {
        Try {
            NameTable nameTable(this->m_connection);
            return nameTable.isPresent(name, owner);
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't check if name and label pair is present");
    }

    void DBCrypto::saveDBRows(const Name &name, const Label &owner, const DBRowVector &rows)
    {
        Try {
            // transaction is present in the layer above
            NameTable nameTable(this->m_connection);
            ObjectTable objectTable(this->m_connection);
            nameTable.addRow(name, owner);
            for (const auto &i: rows)
                objectTable.addRow(i);
            return;
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement: " << _rethrown_exception.GetMessage());
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't save DBRow");
    }

    void DBCrypto::saveDBRow(const DBRow &row) {
        Try {
            // transaction is present in the layer above
            NameTable nameTable(this->m_connection);
            ObjectTable objectTable(this->m_connection);
            nameTable.addRow(row.name, row.ownerLabel);
            objectTable.addRow(row);
            return;
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't save DBRow");
    }

    bool DBCrypto::deleteDBRow(
            const Name &name,
            const Label &ownerLabel)
    {
        Try {
            // transaction is present in the layer above
            NameTable nameTable(this->m_connection);
            if(nameTable.isPresent(name, ownerLabel))
            {
                nameTable.deleteRow(name, ownerLabel);
                return true;
            }
            return false;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare delete statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute delete statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't delete DBRow for name " << name << " using ownerLabel " << ownerLabel);
    }

    DBRow DBCrypto::getRow(
            const Name &name,
            const Label &ownerLabel,
            const SqlConnection::DataCommandUniquePtr &selectCommand) const {
        DBRow row;
        row.name = name;
        row.ownerLabel = ownerLabel;
        row.exportable = selectCommand->GetColumnInteger(0);
        row.dataType = DBDataType(selectCommand->GetColumnInteger(1));
        row.algorithmType = static_cast<DBCMAlgType>(selectCommand->GetColumnInteger(2));
        row.encryptionScheme = selectCommand->GetColumnInteger(3);
        row.iv = selectCommand->GetColumnBlob(4);
        row.dataSize = selectCommand->GetColumnInteger(5);
        row.data = selectCommand->GetColumnBlob(6);
        row.tag = selectCommand->GetColumnBlob(7);
        return row;
    }

    PermissionOptional DBCrypto::getPermissionRow(
        const Name &name,
        const Label &ownerLabel,
        const Label &accessorLabel) const
    {
        Try {
            PermissionTable permissionTable(this->m_connection);
            return permissionTable.getPermissionRow(name, ownerLabel, accessorLabel);
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
                    m_connection->PrepareDataCommand(DB_CMD_OBJECT_SELECT_BY_NAME_AND_LABEL);
            selectCommand->BindInteger(1, typeRangeStart);
            selectCommand->BindInteger(2, typeRangeStop);

            // name table reference
            selectCommand->BindString (101, name.c_str());
            selectCommand->BindString (102, ownerLabel.c_str());

            if(selectCommand->Step())
            {
                // extract data
                DBRow current_row = getRow(name, ownerLabel, selectCommand);

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

    void DBCrypto::getDBRows(
        const Name &name,
        const Label &ownerLabel,
        DBDataType type,
        DBRowVector &output)
    {
        getDBRows(name, ownerLabel, type, type, output);
    }

    void DBCrypto::getDBRows(
        const Name &name,
        const Label &ownerLabel,
        DBDataType typeRangeStart,
        DBDataType typeRangeStop,
        DBRowVector &output)
    {
        Try {
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_connection->PrepareDataCommand(DB_CMD_OBJECT_SELECT_BY_NAME_AND_LABEL);
            selectCommand->BindInteger(1, typeRangeStart);
            selectCommand->BindInteger(2, typeRangeStop);

            // name table reference
            selectCommand->BindString (101, name.c_str());
            selectCommand->BindString (102, ownerLabel.c_str());

            while(selectCommand->Step())
            {
                // extract data
                output.push_back(getRow(name, ownerLabel, selectCommand));
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
                            m_connection->PrepareDataCommand(DB_CMD_NAME_SELECT_BY_TYPE_AND_PERMISSION);
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



    void DBCrypto::saveKey(
            const Label& label,
            const RawBuffer &key)
    {
        Try {
            SqlConnection::DataCommandUniquePtr insertCommand =
                    m_connection->PrepareDataCommand(DB_CMD_KEY_INSERT);
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
                    m_connection->PrepareDataCommand(DB_CMD_KEY_SELECT);
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
                    m_connection->PrepareDataCommand(DB_CMD_KEY_DELETE);
            deleteCommand->BindString(1, label.c_str());
            deleteCommand->Step();

            NameTable nameTable(this->m_connection);
            nameTable.deleteAllRows(label);

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

    void DBCrypto::setPermission(
            const Name &name,
            const Label& ownerLabel,
            const Label& accessorLabel,
            const Permission permissions)
    {
        Try {
            PermissionTable permissionTable(this->m_connection);
            permissionTable.setPermission(name, ownerLabel, accessorLabel, permissions);
            return;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare set statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute set statement");
        }
        ThrowMsg(DBCrypto::Exception::InternalError,
                "Couldn't set permissions for name " << name );
    }

    void DBCrypto::PermissionTable::setPermission(
            const Name &name,
            const Label& ownerLabel,
            const Label& accessorLabel,
            const Permission permissions)
    {
        if(permissions == Permission::NONE)
        {
            // clear permissions
            SqlConnection::DataCommandUniquePtr deletePermissionCommand =
                m_connection->PrepareDataCommand(DB_CMD_PERMISSION_DELETE);
            deletePermissionCommand->BindString(1, accessorLabel.c_str());
            deletePermissionCommand->BindString(101, name.c_str());
            deletePermissionCommand->BindString(102, ownerLabel.c_str());
            deletePermissionCommand->Step();
        }
        else
        {
            // add new permissions
            SqlConnection::DataCommandUniquePtr setPermissionCommand =
                m_connection->PrepareDataCommand(DB_CMD_PERMISSION_SET);
            setPermissionCommand->BindString(1, accessorLabel.c_str());
            setPermissionCommand->BindString(2, toDBPermission(permissions));
            setPermissionCommand->BindString(101, name.c_str());
            setPermissionCommand->BindString(102, ownerLabel.c_str());
            setPermissionCommand->Step();
        }
    }

    PermissionOptional DBCrypto::PermissionTable::getPermissionRow(
            const Name &name,
            const Label &ownerLabel,
            const Label &accessorLabel) const
    {
        SqlConnection::DataCommandUniquePtr selectCommand =
                m_connection->PrepareDataCommand(DB_CMD_PERMISSION_SELECT);
        selectCommand->BindString(1, accessorLabel.c_str());

        // name table reference
        selectCommand->BindString(101, name.c_str());
        selectCommand->BindString(102, ownerLabel.c_str());

        if(selectCommand->Step())
        {
            // there is entry for the <name, ownerLabel> pair
            return PermissionOptional(toPermission(selectCommand->GetColumnString(0)));
        }
        return PermissionOptional();
    }

    void DBCrypto::NameTable::addRow(
            const Name &name,
            const Label &ownerLabel)
    {
        // insert NAME_TABLE item
        SqlConnection::DataCommandUniquePtr insertNameCommand =
                m_connection->PrepareDataCommand(DB_CMD_NAME_INSERT);
        insertNameCommand->BindString (101, name.c_str());
        insertNameCommand->BindString (102, ownerLabel.c_str());
        insertNameCommand->Step();
    }

    void DBCrypto::NameTable::deleteRow(
            const Name &name,
            const Label &ownerLabel)
    {
        SqlConnection::DataCommandUniquePtr deleteCommand =
                m_connection->PrepareDataCommand(DB_CMD_NAME_DELETE);
        deleteCommand->BindString(101, name.c_str());
        deleteCommand->BindString(102, ownerLabel.c_str());

        // Step() result code does not provide information whether
        // anything was removed.
        deleteCommand->Step();
    }

    void DBCrypto::NameTable::deleteAllRows(const Label &ownerLabel)
    {
        SqlConnection::DataCommandUniquePtr deleteData =
                m_connection->PrepareDataCommand(DB_CMD_NAME_DELETE_BY_LABEL);
        deleteData->BindString(102, ownerLabel.c_str());

        // Step() result code does not provide information whether
        // anything was removed.
        deleteData->Step();
    }

    bool DBCrypto::NameTable::isPresent(const Name &name, const Label &ownerLabel) const
    {
        SqlConnection::DataCommandUniquePtr checkCmd =
                m_connection->PrepareDataCommand(DB_CMD_NAME_COUNT_ROWS);
        checkCmd->BindString(101, name.c_str());
        checkCmd->BindString(102, ownerLabel.c_str());
        if(checkCmd->Step()) {
            int element_count = checkCmd->GetColumnInteger(0);
            LogDebug("Item name: " << name  << " ownerLabel: " << ownerLabel <<
                     " hit count: " << element_count);
            if(element_count > 0)
                return true;
        }
        return false;
    }

    void DBCrypto::ObjectTable::addRow(const DBRow &row)
    {
        SqlConnection::DataCommandUniquePtr insertObjectCommand =
                m_connection->PrepareDataCommand(DB_CMD_OBJECT_INSERT);
        insertObjectCommand->BindInteger(1, row.exportable);
        insertObjectCommand->BindInteger(2, static_cast<int>(row.dataType));
        insertObjectCommand->BindInteger(3, static_cast<int>(row.algorithmType));
        insertObjectCommand->BindInteger(4, row.encryptionScheme);
        insertObjectCommand->BindBlob   (5, row.iv);
        insertObjectCommand->BindInteger(6, row.dataSize);
        insertObjectCommand->BindBlob   (7, row.data);
        insertObjectCommand->BindBlob   (8, row.tag);

        // name table reference
        insertObjectCommand->BindString (101, row.name.c_str());
        insertObjectCommand->BindString (102, row.ownerLabel.c_str());

        insertObjectCommand->Step();
    }
} // namespace CKM

#pragma GCC diagnostic pop
