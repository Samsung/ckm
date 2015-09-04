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

#include <fstream>
#include <db-crypto.h>
#include <dpl/db/sql_connection.h>
#include <dpl/log/log.h>
#include <ckm/ckm-error.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

namespace {
    const CKM::PermissionMask DEFAULT_PERMISSIONS =
                        static_cast<CKM::PermissionMask>(CKM::Permission::READ | CKM::Permission::REMOVE);

    const char *SCRIPTS_PATH = "/usr/share/ckm/scripts/";

    enum DBVersion : int {
        DB_VERSION_1                   = 1,
        DB_VERSION_2                   = 2,
        /* ... since version 3, there is no need to manually
         * recognize database version.
         * Remember only that if doing changes to the database,
         * increment and update DB_VERSION_CURRENT,
         * then provide migration mechanism!
         */
        DB_VERSION_CURRENT             = 4
    };

    const char *SCRIPT_CREATE_SCHEMA                = "create_schema";
    const char *SCRIPT_DROP_ALL_ITEMS               = "drop_all";
    const char *SCRIPT_MIGRATE                      = "migrate_";

    // common substitutions:
    // 100 - idx
    // 101 - name
    // 102 - label
    // 103 - value
    // 104 - permissionLabel
    // 105 - permissionMask
    const char *DB_CMD_SCHEMA_SET =
            "REPLACE INTO SCHEMA_INFO(name, value) "
            "   VALUES(?101, ?103);";

    const char *DB_CMD_SCHEMA_GET =
            "SELECT * FROM SCHEMA_INFO WHERE name=?101;";

    const char *DB_SCHEMA_VERSION_FIELD = "schema_version";


    const char *DB_CMD_NAME_INSERT =
            "INSERT INTO NAMES("
            "   name, label) "
            "   VALUES(?101, ?102);";

    const char *DB_CMD_NAME_COUNT_ROWS =
            "SELECT COUNT(idx) FROM NAMES WHERE name=?101 AND label=?102;";

    const char *DB_CMD_NAME_DELETE =
            "DELETE FROM NAMES WHERE name=?101 AND label=?102;";

    const char *DB_CMD_NAME_DELETE_BY_LABEL =
            "DELETE FROM NAMES WHERE label=?102;";


    const char *DB_CMD_OBJECT_INSERT =
            "INSERT INTO OBJECTS("
            "   exportable, dataType,"
            "   algorithmType, encryptionScheme,"
            "   iv, dataSize, data, tag, idx, backendId) "
            "   VALUES(?001, ?002, ?003, ?004, ?005, "
            "          ?006, ?007, ?008,"
            "          (SELECT idx FROM NAMES WHERE name=?101 and label=?102),"
            "          ?009"
            "         );";

    const char *DB_CMD_OBJECT_SELECT_BY_NAME_AND_LABEL =
            "SELECT * FROM [join_name_object_tables] "
            " WHERE (dataType BETWEEN ?001 AND ?002) "
            " AND name=?101 and label=?102;";


    const char *DB_CMD_KEY_INSERT =
            "INSERT INTO KEYS(label, key) VALUES (?, ?);";
    const char *DB_CMD_KEY_SELECT =
            "SELECT key FROM KEYS WHERE label=?;";
    const char *DB_CMD_KEY_DELETE =
            "DELETE FROM KEYS WHERE label=?";


    const char *DB_CMD_PERMISSION_SET = // SQLite does not support updating views
            "REPLACE INTO PERMISSIONS(permissionLabel, permissionMask, idx) "
            " VALUES (?104, ?105, (SELECT idx FROM NAMES WHERE name=?101 and label=?102));";

    const char *DB_CMD_PERMISSION_SELECT =
            "SELECT permissionMask FROM [join_name_permission_tables] "
            " WHERE permissionLabel=?104 "
            " AND name=?101 and label=?102;";

    const char *DB_CMD_PERMISSION_DELETE = // SQLite does not support updating views
            "DELETE FROM PERMISSIONS WHERE permissionLabel=?104 AND "
            " idx=(SELECT idx FROM NAMES WHERE name=?101 and label=?102);";


    /*
     * GROUP BY is necessary because of the following case:
     * -There are several permissions to L1, N1 (label, name) from other accessors. When listing
     *  objects accessible by L1 the query will produce one result (L1, N1) for each allowed
     *  accessor but GROUP BY will reduce them to one so L1 will have (L1, N1) on its list only once
     */
    const char *DB_CMD_NAME_SELECT_BY_TYPE_AND_PERMISSION =
            "SELECT label, name FROM [join_all_tables] "
            " WHERE dataType>=?001 AND dataType<=?002 "
            " AND permissionLabel=?104 AND permissionMask&?004!=0 GROUP BY idx;";
}

namespace CKM {
namespace DB {
    Crypto::Crypto(const std::string& path, const RawBuffer &rawPass)
    {
        m_connection = NULL;
        m_inUserTransaction = false;
        Try {
            m_connection = new SqlConnection(path, SqlConnection::Flag::Option::CRW);
            m_connection->SetKey(rawPass);
            initDatabase();
            m_connection->ExecCommand("VACUUM;");
        } Catch(SqlConnection::Exception::ConnectionBroken) {
            LogError("Couldn't connect to database: " << path);
            ReThrow(Crypto::Exception::InternalError);
        } Catch(SqlConnection::Exception::InvalidArguments) {
            LogError("Couldn't set the key for database");
            ReThrow(Crypto::Exception::InternalError);
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't initiate the database");
            ReThrow(Crypto::Exception::InternalError);
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't create the database");
            ReThrow(Crypto::Exception::InternalError);
        }
    }

    Crypto::Crypto(Crypto &&other) :
            m_connection(other.m_connection),
            m_inUserTransaction(other.m_inUserTransaction)
    {
        other.m_connection = NULL;
        other.m_inUserTransaction = false;
    }

    Crypto::~Crypto() {
        delete m_connection;
    }

    Crypto& Crypto::operator=(Crypto&& other) {
        if (this == &other)
            return *this;
        delete m_connection;

        m_connection = other.m_connection;
        other.m_connection = NULL;

        m_inUserTransaction = other.m_inUserTransaction;
        other.m_inUserTransaction = false;

        return *this;
    }

    void Crypto::createTable(
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

    void Crypto::createView(
            const char* create_cmd)
    {
        Try {
            m_connection->ExecCommand(create_cmd);
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't create view!");
            throw;
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Sqlite got into infinite busy state");
            throw;
        }
    }

    bool Crypto::getDBVersion(int & schemaVersion)
    {
        SchemaInfo SchemaInfo(this);
        if(SchemaInfo.getVersionInfo(schemaVersion)) {
            LogDebug("Current DB version: " << schemaVersion);
            return true;
        }
        else
        {
            LogDebug("No DB version known or DB not present");

            // special case: old CKM_TABLE exists
            if(m_connection->CheckTableExist("CKM_TABLE")) {
                schemaVersion = DB_VERSION_1;
                return true;
            }

            // special case: new scheme exists, but no SCHEMA_INFO table present
            else if(m_connection->CheckTableExist("NAME_TABLE")) {
                schemaVersion = DB_VERSION_2;
                return true;
            }
        }
        // not recognized - proceed with an empty DBs
        return false;
    }

    void Crypto::initDatabase()
    {
        // run migration if old database is present
        int schemaVersion;
        if( getDBVersion(schemaVersion)==false ||       // DB empty or corrupted
            schemaVersion > DB_VERSION_CURRENT)         // or too new scheme
        {
            LogDebug("no database or database corrupted, initializing the DB");
            resetDB();
        }
        else
        {
            // migration needed
            LogDebug("DB migration from version " << schemaVersion << " to version " << DB_VERSION_CURRENT << " started.");
            Transaction transaction(this);
            for(int vi=schemaVersion; vi<DB_VERSION_CURRENT; vi++)
            {
                ScriptOptional script = getMigrationScript(vi);
                if(!script)
                {
                    LogError("Error, script to migrate database from version: " << vi <<
                             " to version: " << vi+1 << " not available, resetting the DB");
                    resetDB();
                    break;
                }

                LogInfo("migrating from version " << vi << " to version " << vi+1);
                m_connection->ExecCommand((*script).c_str());
            }
            // update DB version info
            SchemaInfo SchemaInfo(this);
            SchemaInfo.setVersionInfo();
            transaction.commit();
        }
    }

    Crypto::ScriptOptional Crypto::getScript(const std::string &scriptName) const
    {
        std::string scriptPath = SCRIPTS_PATH + scriptName + std::string(".sql");
        std::ifstream is(scriptPath);
        if(is.fail()) {
            LogError("Script " << scriptPath << " not found!");
            return ScriptOptional();
        }

        std::istreambuf_iterator<char> begin(is),end;
        return ScriptOptional(std::string(begin, end));
    }

    Crypto::ScriptOptional Crypto::getMigrationScript(int db_version) const
    {
        std::string scriptPath = std::string(SCRIPT_MIGRATE) + std::to_string(db_version);
        return getScript(scriptPath);
    }

    void Crypto::createDBSchema() {
        Transaction transaction(this);

        ScriptOptional script = getScript(SCRIPT_CREATE_SCHEMA);
        if(!script)
        {
            std::string errmsg = "Can not create the database schema: no initialization script";
            LogError(errmsg);
            ThrowMsg(Exception::InternalError, errmsg);
        }

        m_connection->ExecCommand((*script).c_str());
        SchemaInfo SchemaInfo(this);
        SchemaInfo.setVersionInfo();
        transaction.commit();
    }

    void Crypto::resetDB() {
        Transaction transaction(this);
        ScriptOptional script = getScript(SCRIPT_DROP_ALL_ITEMS);
        if(!script)
        {
            std::string errmsg = "Can not clear the database: no clearing script";
            LogError(errmsg);
            ThrowMsg(Exception::InternalError, errmsg);
        }

        m_connection->ExecCommand((*script).c_str());
        createDBSchema();
        transaction.commit();
    }

    bool Crypto::isNameLabelPresent(const Name &name, const Label &owner) const {
        Try {
            NameTable nameTable(this->m_connection);
            return nameTable.isPresent(name, owner);
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't check if name and label pair is present");
    }

    void Crypto::saveRows(const Name &name, const Label &owner, const RowVector &rows)
    {
        Try {
            // transaction is present in the layer above
            NameTable nameTable(this->m_connection);
            ObjectTable objectTable(this->m_connection);
            PermissionTable permissionTable(this->m_connection);
            nameTable.addRow(name, owner);
            for (const auto &i: rows)
                objectTable.addRow(i);
            permissionTable.setPermission(name,
                                          owner,
                                          owner,
                                          static_cast<int>(DEFAULT_PERMISSIONS));
            return;
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement: " << _rethrown_exception.GetMessage());
        }
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't save Row");
    }

    void Crypto::saveRow(const Row &row) {
        Try {
            // transaction is present in the layer above
            NameTable nameTable(this->m_connection);
            ObjectTable objectTable(this->m_connection);
            PermissionTable permissionTable(this->m_connection);
            nameTable.addRow(row.name, row.ownerLabel);
            objectTable.addRow(row);
            permissionTable.setPermission(row.name,
                                          row.ownerLabel,
                                          row.ownerLabel,
                                          static_cast<int>(DEFAULT_PERMISSIONS));
            return;
        } Catch(SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare insert statement");
        } Catch(SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute insert statement");
        }
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't save Row");
    }

    bool Crypto::deleteRow(
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
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't delete Row for name " << name << " using ownerLabel " << ownerLabel);
    }

    Row Crypto::getRow(
            const SqlConnection::DataCommandUniquePtr &selectCommand) const {
        Row row;
        row.name = selectCommand->GetColumnString(0);
        row.ownerLabel = selectCommand->GetColumnString(1);
        row.exportable = selectCommand->GetColumnInteger(2);
        row.dataType = DataType(selectCommand->GetColumnInteger(3));
        row.algorithmType = static_cast<DBCMAlgType>(selectCommand->GetColumnInteger(4));
        row.encryptionScheme = selectCommand->GetColumnInteger(5);
        row.iv = selectCommand->GetColumnBlob(6);
        row.dataSize = selectCommand->GetColumnInteger(7);
        row.data = selectCommand->GetColumnBlob(8);
        row.tag = selectCommand->GetColumnBlob(9);
        row.backendId = static_cast<CryptoBackend>(selectCommand->GetColumnInteger(11));
        return row;
    }

    PermissionMaskOptional Crypto::getPermissionRow(
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
        return PermissionMaskOptional();
    }

    Crypto::RowOptional Crypto::getRow(
        const Name &name,
        const Label &ownerLabel,
        DataType type)
    {
        return getRow(name, ownerLabel, type, type);
    }

    Crypto::RowOptional Crypto::getRow(
        const Name &name,
        const Label &ownerLabel,
        DataType typeRangeStart,
        DataType typeRangeStop)
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
                Row current_row = getRow(selectCommand);

                // all okay, proceed
                return RowOptional(current_row);
            } else {
                return RowOptional();
            }
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
        }
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't get row of type <" <<
                static_cast<int>(typeRangeStart) << "," <<
                static_cast<int>(typeRangeStop)  << ">" <<
                " name " << name << " with owner label " << ownerLabel);
    }

    void Crypto::getRows(
        const Name &name,
        const Label &ownerLabel,
        DataType type,
        RowVector &output)
    {
        getRows(name, ownerLabel, type, type, output);
    }

    void Crypto::getRows(
        const Name &name,
        const Label &ownerLabel,
        DataType typeRangeStart,
        DataType typeRangeStop,
        RowVector &output)
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
                output.push_back(getRow(selectCommand));
            }
            return;
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
        }
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't get row of type <" <<
                static_cast<int>(typeRangeStart) << "," <<
                static_cast<int>(typeRangeStop)  << ">" <<
                " name " << name << " with owner label " << ownerLabel);
    }

    void Crypto::listNames(
        const Label &smackLabel,
        LabelNameVector& labelNameVector,
        DataType type)
    {
        listNames(smackLabel, labelNameVector, type, type);
    }

    void Crypto::listNames(
        const Label &smackLabel,
        LabelNameVector& labelNameVector,
        DataType typeRangeStart,
        DataType typeRangeStop)
    {
        Try{
            Transaction transaction(this);
            SqlConnection::DataCommandUniquePtr selectCommand =
                            m_connection->PrepareDataCommand(DB_CMD_NAME_SELECT_BY_TYPE_AND_PERMISSION);
            selectCommand->BindInteger(1, static_cast<int>(typeRangeStart));
            selectCommand->BindInteger(2, static_cast<int>(typeRangeStop));
            selectCommand->BindString(104, smackLabel.c_str());
            selectCommand->BindInteger(4, static_cast<int>(Permission::READ | Permission::REMOVE));

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
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't list names of type <" <<
                static_cast<int>(typeRangeStart) << "," <<
                static_cast<int>(typeRangeStop)  << ">" <<
                " accessible to client label " << smackLabel);
    }



    void Crypto::saveKey(
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
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't save key for label " << label);
    }

    Crypto::RawBufferOptional Crypto::getKey(const Label& label)
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
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't get key for label " << label);
    }

    void Crypto::deleteKey(const Label& label) {
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
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't delete key for label " << label);
    }

    void Crypto::setPermission(
            const Name &name,
            const Label& ownerLabel,
            const Label& accessorLabel,
            const PermissionMask permissionMask)
    {
        Try {
            PermissionTable permissionTable(this->m_connection);
            permissionTable.setPermission(name, ownerLabel, accessorLabel, permissionMask);
            return;
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare set statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute set statement");
        }
        ThrowMsg(Crypto::Exception::InternalError,
                "Couldn't set permissions for name " << name );
    }


    void Crypto::SchemaInfo::setVersionInfo() {
        SqlConnection::DataCommandUniquePtr insertContextCommand =
                m_db->m_connection->PrepareDataCommand(DB_CMD_SCHEMA_SET);
        insertContextCommand->BindString(101, DB_SCHEMA_VERSION_FIELD);
        insertContextCommand->BindString(103, std::to_string(DB_VERSION_CURRENT).c_str());
        insertContextCommand->Step();
    }

    bool Crypto::SchemaInfo::getVersionInfo(int & version) const
    {
        // Try..Catch mandatory here - we don't need to escalate the error
        // if it happens - we just won't return the version, allowing CKM to work
        Try {
            SqlConnection::DataCommandUniquePtr selectCommand =
                    m_db->m_connection->PrepareDataCommand(DB_CMD_SCHEMA_GET);
            selectCommand->BindString(101, DB_SCHEMA_VERSION_FIELD);

            if(selectCommand->Step()) {
                version = static_cast<int>(atoi(selectCommand->GetColumnString(1).c_str()));
                return true;
            }
        } Catch (SqlConnection::Exception::InvalidColumn) {
            LogError("Select statement invalid column error");
        } Catch (SqlConnection::Exception::SyntaxError) {
            LogError("Couldn't prepare select statement");
        } Catch (SqlConnection::Exception::InternalError) {
            LogError("Couldn't execute select statement");
        }
        return false;
    }

    void Crypto::PermissionTable::setPermission(
            const Name &name,
            const Label& ownerLabel,
            const Label& accessorLabel,
            const PermissionMask permissionMask)
    {
        if(permissionMask == Permission::NONE)
        {
            // clear permissions
            SqlConnection::DataCommandUniquePtr deletePermissionCommand =
                m_connection->PrepareDataCommand(DB_CMD_PERMISSION_DELETE);
            deletePermissionCommand->BindString(104, accessorLabel.c_str());
            deletePermissionCommand->BindString(101, name.c_str());
            deletePermissionCommand->BindString(102, ownerLabel.c_str());
            deletePermissionCommand->Step();
        }
        else
        {
            // add new permissions
            SqlConnection::DataCommandUniquePtr setPermissionCommand =
                m_connection->PrepareDataCommand(DB_CMD_PERMISSION_SET);
            setPermissionCommand->BindString(104, accessorLabel.c_str());
            setPermissionCommand->BindInteger(105, static_cast<int>(permissionMask));
            setPermissionCommand->BindString(101, name.c_str());
            setPermissionCommand->BindString(102, ownerLabel.c_str());
            setPermissionCommand->Step();
        }
    }

    PermissionMaskOptional Crypto::PermissionTable::getPermissionRow(
            const Name &name,
            const Label &ownerLabel,
            const Label &accessorLabel) const
    {
        SqlConnection::DataCommandUniquePtr selectCommand =
                m_connection->PrepareDataCommand(DB_CMD_PERMISSION_SELECT);
        selectCommand->BindString(104, accessorLabel.c_str());

        // name table reference
        selectCommand->BindString(101, name.c_str());
        selectCommand->BindString(102, ownerLabel.c_str());

        if(selectCommand->Step())
        {
            // there is entry for the <name, ownerLabel> pair
            return PermissionMaskOptional(PermissionMask(selectCommand->GetColumnInteger(0)));
        }
        return PermissionMaskOptional();
    }

    void Crypto::NameTable::addRow(
            const Name &name,
            const Label &ownerLabel)
    {
        // insert NAMES item
        SqlConnection::DataCommandUniquePtr insertNameCommand =
                m_connection->PrepareDataCommand(DB_CMD_NAME_INSERT);
        insertNameCommand->BindString (101, name.c_str());
        insertNameCommand->BindString (102, ownerLabel.c_str());
        insertNameCommand->Step();
    }

    void Crypto::NameTable::deleteRow(
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

    void Crypto::NameTable::deleteAllRows(const Label &ownerLabel)
    {
        SqlConnection::DataCommandUniquePtr deleteData =
                m_connection->PrepareDataCommand(DB_CMD_NAME_DELETE_BY_LABEL);
        deleteData->BindString(102, ownerLabel.c_str());

        // Step() result code does not provide information whether
        // anything was removed.
        deleteData->Step();
    }

    bool Crypto::NameTable::isPresent(const Name &name, const Label &ownerLabel) const
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

    void Crypto::ObjectTable::addRow(const Row &row)
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
        insertObjectCommand->BindInteger(9, static_cast<int>(row.backendId));

        // name table reference
        insertObjectCommand->BindString (101, row.name.c_str());
        insertObjectCommand->BindString (102, row.ownerLabel.c_str());

        insertObjectCommand->Step();
    }
} // namespace DB
} // namespace CKM

#pragma GCC diagnostic pop
