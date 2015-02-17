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
#include <protocols.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

namespace CKM {
    class DBCrypto {
         public:
            typedef boost::optional<DBRow> DBRowOptional;
            typedef boost::optional<RawBuffer> RawBufferOptional;
            class Exception
            {
              public:
                DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
                DECLARE_EXCEPTION_TYPE(Base, NameExists)
                DECLARE_EXCEPTION_TYPE(Base, InternalError)
                DECLARE_EXCEPTION_TYPE(Base, TransactionError)
                DECLARE_EXCEPTION_TYPE(Base, PermissionDenied)
                DECLARE_EXCEPTION_TYPE(Base, InvalidArgs)
            };
            DBCrypto() :
                m_connection(NULL),
                m_inUserTransaction(false)
              {};
            //user name instead of path?
            DBCrypto(const std::string &path, const RawBuffer &rawPass);
            DBCrypto(const DBCrypto &other) = delete;
            DBCrypto(DBCrypto &&other);

            DBCrypto& operator=(const DBCrypto& ) = delete;
            DBCrypto& operator=(DBCrypto&& other);

            virtual ~DBCrypto();

            void saveDBRow(const DBRow &row);
            DBRowOptional getDBRow(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &smackLabel,
                    DBDataType type);
            DBRowOptional getKeyDBRow(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &smackLabel);
            void getNames(
                    const Label &clnt_label,
                    DBDataType dataType,
                    LabelNameVector &labelNameVector);
            void getKeyNames(
                    const Label &clnt_label,
                    LabelNameVector &labelNameVector);
            bool deleteDBRow(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &smackLabel);

            // keys
            void saveKey(const Label& label, const RawBuffer &key);
            RawBufferOptional getKey(const Label& label);
            void deleteKey(const Label& label);

            // permissions
            int setAccessRights(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &accessorLabel,
                    const AccessRight rights);
            int clearAccessRights(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &accessorLabel);

            int beginTransaction();
            int commitTransaction();
            int rollbackTransaction();

            class Transaction {
            public:
                Transaction(DBCrypto *db)
                    : m_db(db),
                      m_inTransaction(false) {
                    if(!m_db->m_inUserTransaction) {
                        Try {
                            m_db->m_connection->ExecCommand("BEGIN EXCLUSIVE");
                            m_db->m_inUserTransaction = true;
                            m_inTransaction = true;
                        } Catch (DB::SqlConnection::Exception::InternalError) {
                            LogError("sqlite got into infinite busy state");
                            ReThrow(DBCrypto::Exception::TransactionError);
                        } Catch (DB::SqlConnection::Exception::Base) {
                            LogError("Couldn't begin transaction");
                            ReThrow(DBCrypto::Exception::TransactionError);
                        }
                    }
                }
                void commit() {
                    if(m_inTransaction) {
                        Try {
                            m_db->m_connection->CommitTransaction();
                            m_db->m_inUserTransaction = false;
                            m_inTransaction = false;
                        } Catch (DB::SqlConnection::Exception::InternalError) {
                            LogError("sqlite got into infinite busy state");
                            ReThrow(DBCrypto::Exception::TransactionError);
                        } Catch (DB::SqlConnection::Exception::Base) {
                            LogError("Couldn't commit transaction");
                            ReThrow(DBCrypto::Exception::TransactionError);
                        }
                    }
                }
                void rollback() {
                    if(m_inTransaction) {
                        Try {
                            m_db->m_connection->RollbackTransaction();
                            m_db->m_inUserTransaction = false;
                            m_inTransaction = false;
                        } Catch (DB::SqlConnection::Exception::InternalError) {
                            LogError("sqlite got into infinite busy state");
                            ReThrow(DBCrypto::Exception::TransactionError);
                        } Catch (DB::SqlConnection::Exception::Base) {
                            LogError("Couldn't rollback transaction");
                            ReThrow(DBCrypto::Exception::TransactionError);
                        }
                    }
                }
                ~Transaction() {
                    Try {
                        if(m_inTransaction) {
                            m_db->m_inUserTransaction = false;
                            m_db->m_connection->RollbackTransaction();
                        }
                    } Catch (DB::SqlConnection::Exception::InternalError) {
                        LogError("sqlite got into infinite busy state");
                        ReThrow(DBCrypto::Exception::TransactionError);
                    } Catch (DB::SqlConnection::Exception::Base) {
                        LogError("Transaction rollback failed!");
                    }
                }
            private:
                DBCrypto *m_db;
                bool m_inTransaction;
            };

         private:
            DB::SqlConnection* m_connection;
            bool m_inUserTransaction;

            void initDatabase();
            DBRow getRow(const DB::SqlConnection::DataCommandUniquePtr &selectCommand);

            enum DBOperationType : char {
                DB_OPERATION_READ       = 'R',            ///< read DB row
                DB_OPERATION_WRITE      = 'W',            ///< modify DB row
                DB_OPERATION_REMOVE     = 'D'             ///< delete DB row
            };

            /**
             * read PERMISSION_TABLE entry for client smackLabel to access CKM entry <name, ownerLabel>
             *
             * @return permission string (consisting with DBOperationType chars), may be empty
             */
            std::string getPermissions(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &smackLabel) const;

            void createTable(
                    const char *create_cmd,
                    const char *table_name);
            bool checkNameExist(const Name &name, const Label &owner) const;
//            void getLabelForName(const Name &name, Label & label) const;
//            void getLabelForName(const Name &name, Label & label, int & index) const;
            bool checkGlobalNameExist(const Name &name, const Label &ownerLabel) const;
            void getSingleType(const Label &clnt_label, DBDataType type, LabelNameVector& labelNameVector) const;
            DBRowOptional getDBRowSimple(
                    const Name &name,
                    const Label &ownerLabel,
                    DBDataType type);

            DBRowOptional getDBRowJoin(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &smackLabel,
                    DBDataType type);

            DBRowOptional getKeyDBRowSimple(
                    const Name &name,
                    const Label &onwerLabel);

            DBRowOptional getKeyDBRowJoin(
                    const Name &name,
                    const Label &onwerLabel,
                    const Label &smackLabel);

            int countRows(
                    const Name &name,
                    const Label &label);

            bool deleteDBRowSimple(
                    const Name &name,
                    const Label &ownerLabel);

            bool deleteDBRowJoin(
                    const Name &name,
                    const Label &ownerLabel,
                    const Label &smackLabel);
    };
} // namespace CKM

#pragma GCC diagnostic pop
#endif //DB_CRYPTO_H

