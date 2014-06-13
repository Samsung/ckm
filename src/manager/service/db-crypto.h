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


namespace CKM {
    class DBCrypto {
         public:
            DBCrypto() : m_connection(NULL), m_init(false) {};
            //user name instead of path?
            DBCrypto(const std::string &path, const RawBuffer &rawPass);
            DBCrypto(const DBCrypto &other) = delete;
            DBCrypto(DBCrypto &&other);

            DBCrypto& operator=(const DBCrypto& ) = delete;
            DBCrypto& operator=(DBCrypto&& other);

            virtual ~DBCrypto();

            bool isInit() {return m_init;};
            int saveDBRow(const DBRow &row);
            int getDBRow(
                    const Alias &alias,
                    const std::string &label,
                    DBDataType type,
                    DBRow &row);
            int getKeyDBRow(
                    const Alias &alias,
                    const std::string &label,
                    DBRow &row);
            int getAliases(
                    DBDataType dataType,
                    const std::string &label,
                    AliasVector &aliases);
            int getKeyAliases(
                    const std::string &label,
                    AliasVector &aliases);
            int deleteDBRow(
                    const Alias& alias,
                    const std::string &label);

            int saveKey(const std::string& label, const RawBuffer &key);
            int getKey(const std::string& label, RawBuffer &key);
            int deleteKey(const std::string& label);

         private:
            DB::SqlConnection* m_connection;
            bool m_init;

            void initDatabase();
            DBRow getRow(const DB::SqlConnection::DataCommandAutoPtr &selectCommand);
            void createTable(const char* create_cmd);
            bool checkAliasExist(
                    const std::string &alias,
                    const std::string &label);
            bool checkGlobalAliasExist(const std::string& alias);
            int getSingleType(
                    DBDataType type,
                    const std::string& label,
                    AliasVector& aliases);

   };
} // namespace CKM

#endif //DB_CRYPTO_H
