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
 * @file        sql_connection.h
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of SQL connection
 */
#ifndef CKM_SQL_CONNECTION_H
#define CKM_SQL_CONNECTION_H

#include <dpl/noncopyable.h>
#include <dpl/exception.h>
#include <dpl/availability.h>
#include <memory>
#include <boost/optional.hpp>
#include <dpl/string.h>
#include <dpl/log/log.h>
#include <sqlcipher.h>
#include <string>
#include <dpl/assert.h>
#include <stdint.h>
#include <vector>

namespace CKM {
namespace DB {
/**
 * SQL connection class
 */
class SqlConnection
{
  public:
    /**
     * SQL Exception classes
     */
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, SyntaxError)
        DECLARE_EXCEPTION_TYPE(Base, ConnectionBroken)
        DECLARE_EXCEPTION_TYPE(Base, InternalError)
        DECLARE_EXCEPTION_TYPE(Base, InvalidColumn)
        DECLARE_EXCEPTION_TYPE(Base, InvalidArguments)
    };

    typedef int ColumnIndex;
    typedef int ArgumentIndex;

    /*
     * SQL processed data command
     */
    class DataCommand :
        private Noncopyable
    {
      private:
        SqlConnection *m_masterConnection;
        sqlcipher3_stmt *m_stmt;

        void CheckBindResult(int result);
        void CheckColumnIndex(SqlConnection::ColumnIndex column);

        DataCommand(SqlConnection *connection, const char *buffer);

        friend class SqlConnection;

      public:
        virtual ~DataCommand();

        /**
         * Bind null to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         */
        void BindNull(ArgumentIndex position);

        /**
         * Bind int to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInteger(ArgumentIndex position, int value);

        /**
         * Bind int8_t to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInt8(ArgumentIndex position, int8_t value);

        /**
         * Bind int16 to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInt16(ArgumentIndex position, int16_t value);

        /**
         * Bind int32 to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInt32(ArgumentIndex position, int32_t value);

        /**
         * Bind int64 to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInt64(ArgumentIndex position, int64_t value);

        /**
         * Bind float to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindFloat(ArgumentIndex position, float value);

        /**
         * Bind double to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindDouble(ArgumentIndex position, double value);

        /**
         * Bind string to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindString(ArgumentIndex position, const char *value);

        /**
         * Bind string to the prepared statement argument
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindString(ArgumentIndex position, const String& value);

        /**
         * Bind optional int to the prepared statement argument.
         * If optional is not set null will be bound
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInteger(ArgumentIndex position, const boost::optional<int> &value);

        /**
         * Bind optional int8 to the prepared statement argument.
         * If optional is not set null will be bound
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInt8(ArgumentIndex position, const boost::optional<int8_t> &value);

        /**
         * Bind optional int16 to the prepared statement argument.
         * If optional is not set null will be bound
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInt16(ArgumentIndex position, const boost::optional<int16_t> &value);

        /**
         * Bind optional int32 to the prepared statement argument.
         * If optional is not set null will be bound
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInt32(ArgumentIndex position, const boost::optional<int32_t> &value);

        /**
         * Bind optional int64 to the prepared statement argument.
         * If optional is not set null will be bound
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindInt64(ArgumentIndex position, const boost::optional<int64_t> &value);

        /**
         * Bind optional float to the prepared statement argument.
         * If optional is not set null will be bound
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindFloat(ArgumentIndex position, const boost::optional<float> &value);

        /**
         * Bind optional double to the prepared statement argument.
         * If optional is not set null will be bound
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindDouble(ArgumentIndex position, const boost::optional<double> &value);

        /**
         * Bind optional string to the prepared statement argument.
         * If optional is not set null will be bound
         *
         * @param position Index of argument to bind value to
         * @param value Value to bind
         */
        void BindString(ArgumentIndex position, const boost::optional<String> &value);

        /**
         * Execute the prepared statement and/or move
         * to the next row of the result
         *
         * @return True when there was a row returned
         */
        bool Step();

        /**
         * Reset prepared statement's arguments
         * All parameters will become null
         */
        void Reset();

        /**
         * Checks whether column value is null
         *
         * @throw Exception::InvalidColumn
         */
        bool IsColumnNull(ColumnIndex column);

        /**
         * Get integer value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        int GetColumnInteger(ColumnIndex column);

        /**
         * Get int8 value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        int8_t GetColumnInt8(ColumnIndex column);

        /**
         * Get int16 value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        int16_t GetColumnInt16(ColumnIndex column);
        /**
         * Get int32 value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        int32_t GetColumnInt32(ColumnIndex column);

        /**
         * Get int64 value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        int64_t GetColumnInt64(ColumnIndex column);

        /**
         * Get float value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        float GetColumnFloat(ColumnIndex column);

        /**
         * Get double value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        double GetColumnDouble(ColumnIndex column);

        /**
         * Get string value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        std::string GetColumnString(ColumnIndex column);

        /**
         * Get optional integer value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        boost::optional<int> GetColumnOptionalInteger(ColumnIndex column);

        /**
         * Get optional int8 value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        boost::optional<int8_t> GetColumnOptionalInt8(ColumnIndex column);

        /**
         * Get optional int16value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        boost::optional<int16_t> GetColumnOptionalInt16(ColumnIndex column);

        /**
         * Get optional int32 value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        boost::optional<int32_t> GetColumnOptionalInt32(ColumnIndex column);

        /**
         * Get optional int64 value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        boost::optional<int64_t> GetColumnOptionalInt64(ColumnIndex column);

        /**
         * Get optional float value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        boost::optional<float> GetColumnOptionalFloat(ColumnIndex column);

        /**
         * Get optional double value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        boost::optional<double> GetColumnOptionalDouble(ColumnIndex column);

        /**
         * Get optional string value from column in current row.
         *
         * @throw Exception::InvalidColumn
         */
        boost::optional<String> GetColumnOptionalString(ColumnIndex column);
    };

    // Move on copy semantics
    typedef std::auto_ptr<DataCommand> DataCommandAutoPtr;

    // Open flags
    class Flag
    {
      public:
        enum Option
        {
            RO = SQLCIPHER_OPEN_NOMUTEX | SQLCIPHER_OPEN_READONLY,
            RW = SQLCIPHER_OPEN_NOMUTEX | SQLCIPHER_OPEN_READWRITE, 
            CRW = RW | SQLCIPHER_OPEN_CREATE
        };
    };

    // RowID
    typedef sqlcipher3_int64 RowID;

    /**
     * Synchronization object used to synchronize SQL connection
     * to the same database across different threads and processes
     */
    class SynchronizationObject
    {
      public:
        virtual ~SynchronizationObject() {}

        /**
         * Synchronizes SQL connection for multiple clients.
         */
        virtual void Synchronize() = 0;

        /**
         * Notify all waiting clients that the connection is no longer locked.
         */
        virtual void NotifyAll() = 0;
    };

  protected:
    sqlcipher3 *m_connection;

    // Options

    // Stored data procedures
    int m_dataCommandsCount;

    // Synchronization object
    std::unique_ptr<SynchronizationObject> m_synchronizationObject;

    bool m_isKeySet;

    virtual void Connect(const std::string &address,
                         Flag::Option = Flag::RO);
    virtual void Disconnect();

    void TurnOnForeignKeys();

    static SynchronizationObject *AllocDefaultSynchronizationObject();

  public:
    /**
     * Open SQL connection
     *
     * Synchronization is archieved by using provided asynchronization object.
     * If synchronizationObject is set to NULL, so synchronization is performed.
     * Ownership of the synchronization object is transfered to sql connection
     * object.
     *
     * @param address Database file name
     * @param flags Open flags
     * @param synchronizationObject A synchronization object to use.
     */
    explicit SqlConnection(const std::string &address = std::string(),
                           Flag::Option options = Flag::RO,
                           SynchronizationObject *synchronizationObject =
                               AllocDefaultSynchronizationObject());

    /**
     * Destructor
     */
    virtual ~SqlConnection();

    /**
     * Added extension for encryption functionality:
     *
     * SetKey gives sqlcipher key, which will be used to encrypt the database
     * This function will only fail because of invalid arguments. To check if
     * database can be opened with provided key, it is necessary to perform
     * some operation on the database (i.e. read from it) and confirm if it
     * succeeds.
     * Password must have length >= 1.
     *
     * @param rawPass password given in raw binary format
     */
    void SetKey(const std::vector<unsigned char> &rawPass);

    /**
     * ResetKey is used for changing key used for database encryption.
     * If key was already set by using SetKey, this function will only change it.
     * If no key was yet set, this function first will set key with rawPassOld and
     * then change it to rawPassNew.
     * Same rules for failing apply as for SetKey.
     * Both password must have length >=1.
     *
     * @param rawPassOld current password for encryption in raw binary format
     * @param rawPassNew new password for encryption in raw binary format
     *
     */
    void ResetKey(const std::vector<unsigned char> &rawPassOld,
                  const std::vector<unsigned char> &rawPassNew);

    /**
     * Execute SQL command without result
     *
     * @param format
     * @param ...
     */
    void ExecCommand(const char *format, ...) CKM_DEPRECATED_WITH_MESSAGE(
            "To prevent sql injection do not use this \
             method for direct sql execution");

    /**
     * Execute BEGIN; command to start new transaction
     *
     */
    void BeginTransaction();

    /**
     * Execute ROLLBACK; command to discard changes made
     *
     */
    void RollbackTransaction();

    /**
     * Execute COMMIT; command to commit changes in database
     *
     */
    void CommitTransaction();

    /**
     * Prepare stored procedure
     *
     * @param format SQL statement
     * @return Data command representing stored procedure
     */
    DataCommandAutoPtr PrepareDataCommand(const char *format, ...);

    /**
     * Check whether given table exists
     *
     * @param tableName Name of the table to check
     * @return True if given table name exists
     */
    bool CheckTableExist(const char *tableName);

    /**
     * Get last insert operation new row id
     *
     * @return Row ID
     */
    RowID GetLastInsertRowID() const;
};
} // namespace DB
} // namespace CKM

#endif // CKM_SQL_CONNECTION_H
