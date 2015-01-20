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
 * @file        db-crypto.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Header of encrypted db access layer
 */

#ifndef DB_CRYPTO_H
#define DB_CRYPTO_H

#include <vector>
#include <string>

#include <dpl/db/sql_connection.h>

#include <ckm/ckm-type.h>
#include <db-row.h>
#include <permission.h>
#include <protocols.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

namespace CKM {
namespace DB {
    class Crypto {
         public:
            typedef boost::optional<Row> RowOptional;
            typedef boost::optional<RawBuffer> RawBufferOptional;
            class Exception
            {
            public:
                DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
                DECLARE_EXCEPTION_TYPE(Base, InternalError)
                DECLARE_EXCEPTION_TYPE(Base, TransactionError)
                DECLARE_EXCEPTION_TYPE(Base, InvalidArgs)
            };
            Crypto() :
                m_connection(NULL),
                m_inUserTransaction(false)
              {};
            // user name instead of path?
            Crypto(const std::string &path, const RawBuffer &rawPass);
            Crypto(const Crypto &other) = delete;
            Crypto(Crypto &&other);

            Crypto& operator=(const Crypto& ) = delete;
            Crypto& operator=(Crypto&& other);

            virtual ~Crypto();

            void saveRow(
                    const Row &row);

            void saveRows(
                    const Name &name,
                    const Label &owner,
                    const RowVector &rows);

            bool isNameLabelPresent(
                    const Name &name,
                    const Label &owner) const;

            RowOptional getRow(
                    const Name &name,
                    const Label &ownerLabel,
                    DataType type);

            RowOptional getRow(
                    const Name &name,
                    const Label &ownerLabel,
                    DataType typeRangeStart,
                    DataType typeRangeStop);

            void getRows(
                    const Name &name,
                    const Label &ownerLabel,
                    DataType type,
                    RowVector &output);

            void getRows(
                    const Name &name,
                    const Label &ownerLabel,
                    DataType typeRangeStart,
                    DataType typeRangeStop,
                    RowVector &output);

            void listNames(
                    const Label &smackLabel,
                    LabelNameVector& labelNameVector,
                    DataType type);

            void listNames(
                    const Label &smackLabel,
                    LabelNameVector& labelNameVector,
                    DataType typeRangeStart,
                    DataType typeRangeStop);

            bool deleteRow(
                    const Name &name,
                    const Label &ownerLabel);

            // keys
            void saveKey(const Label& label, const RawBuffer &key);
            RawBufferOptional getKey(const Label& label);
            void deleteKey(const Label& label);


            // permissions
            void setPermission(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &accessorLabel,
                    const PermissionMask permissionMask);

            PermissionMaskOptional getPermissionRow(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &accessorLabel) const;


            // transactions
            int beginTransaction();
            int commitTransaction();
            int rollbackTransaction();

            class Transaction {
            public:
                Transaction(Crypto *db)
                    : m_db(db),
                      m_inTransaction(false) {
                    if(!m_db->m_inUserTransaction) {
                        Try {
                            m_db->m_connection->ExecCommand("BEGIN EXCLUSIVE");
                            m_db->m_inUserTransaction = true;
                            m_inTransaction = true;
                        } Catch (SqlConnection::Exception::InternalError) {
                            LogError("sqlite got into infinite busy state");
                            ReThrow(Crypto::Exception::TransactionError);
                        } Catch (SqlConnection::Exception::Base) {
                            LogError("Couldn't begin transaction");
                            ReThrow(Crypto::Exception::TransactionError);
                        }
                    }
                }
                void commit() {
                    if(m_inTransaction) {
                        Try {
                            m_db->m_connection->CommitTransaction();
                            m_db->m_inUserTransaction = false;
                            m_inTransaction = false;
                        } Catch (SqlConnection::Exception::InternalError) {
                            LogError("sqlite got into infinite busy state");
                            ReThrow(Crypto::Exception::TransactionError);
                        } Catch (SqlConnection::Exception::Base) {
                            LogError("Couldn't commit transaction");
                            ReThrow(Crypto::Exception::TransactionError);
                        }
                    }
                }
                void rollback() {
                    if(m_inTransaction) {
                        Try {
                            m_db->m_connection->RollbackTransaction();
                            m_db->m_inUserTransaction = false;
                            m_inTransaction = false;
                        } Catch (SqlConnection::Exception::InternalError) {
                            LogError("sqlite got into infinite busy state");
                            ReThrow(Crypto::Exception::TransactionError);
                        } Catch (SqlConnection::Exception::Base) {
                            LogError("Couldn't rollback transaction");
                            ReThrow(Crypto::Exception::TransactionError);
                        }
                    }
                }
                ~Transaction() {
                    Try {
                        if(m_inTransaction) {
                            m_db->m_inUserTransaction = false;
                            m_db->m_connection->RollbackTransaction();
                        }
                    } Catch (SqlConnection::Exception::InternalError) {
                        LogError("sqlite got into infinite busy state");
                        ReThrow(Crypto::Exception::TransactionError);
                    } Catch (SqlConnection::Exception::Base) {
                        LogError("Transaction rollback failed!");
                    }
                }
            private:
                Crypto *m_db;
                bool m_inTransaction;
            };

         private:
            SqlConnection* m_connection;
            bool m_inUserTransaction;

            void resetDB();
            void initDatabase();
            void createDBSchema();
            /**
             * return current database version
             *
             * @param[out] schemaVersion    if success, will contain DB schema version code
             *
             * @return false on DB empty or corrupted, true if information read
             */
            bool getDBVersion(int & schemaVersion);
            typedef boost::optional<std::string> ScriptOptional;
            ScriptOptional getScript(const std::string &scriptName) const;
            ScriptOptional getMigrationScript(int db_version) const;

            Row getRow(
                    const SqlConnection::DataCommandUniquePtr &selectCommand) const;

            void createTable(
                    const char *create_cmd,
                    const char *table_name);

            void createView(
                    const char* create_cmd);

            class SchemaInfo {
            public:
                explicit SchemaInfo(const Crypto *db) : m_db(db) {}

                void        setVersionInfo();
                bool        getVersionInfo(int & version) const;

            private:
                const Crypto *m_db;
            };

        public:
            class NameTable {
            public:
                explicit NameTable(SqlConnection* connection) : m_connection(connection) {}

                void addRow(
                        const Name &name,
                        const Label &ownerLabel);

                void deleteRow(
                        const Name &name,
                        const Label &ownerLabel);

                void deleteAllRows(
                        const Label &ownerLabel);

                bool isPresent(
                        const Name &name,
                        const Label &ownerLabel) const;

            private:
                SqlConnection* m_connection;
            };

            class ObjectTable {
            public:
                explicit ObjectTable(SqlConnection* connection) : m_connection(connection) {}

                void addRow(
                        const Row &row);

            private:
                SqlConnection* m_connection;
            };

            class PermissionTable {
            public:
                explicit PermissionTable(SqlConnection* connection) : m_connection(connection) {}

                void setPermission(
                        const Name &name,
                        const Label &ownerLabel,
                        const Label &accessorLabel,
                        const PermissionMask permissionMask);

                PermissionMaskOptional getPermissionRow(
                        const Name &name,
                        const Label &ownerLabel,
                        const Label &accessorLabel) const;

            private:
                SqlConnection* m_connection;
            };
    };
} // namespace DB
} // namespace CKM

#pragma GCC diagnostic pop
#endif //DB_CRYPTO_H

