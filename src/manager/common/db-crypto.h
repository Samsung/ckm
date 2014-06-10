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
#include <ckm/ckm-type.h>
#include <dpl/db/sql_connection.h>
#include <protocols.h>

namespace CKM {
    struct DBRow {
        std::string alias;
        std::string smackLabel;
        int restricted;
        int exportable;
        DBDataType dataType;        // cert/key/data
        int algorithmType;          // AES mode ?
        int encryptionScheme;       // for example: (ENCR_BASE64 | ENCR_PASSWORD)
        RawBuffer iv;               // encoded in base64
        int dataSize;               // size of information without hash and padding
        RawBuffer data;
    };
    enum class DBCryptoReturn : int {
        DBCRYPTO_SUCCESS = 0,
        DBCRYPTO_ERROR_NO_ROW,
        DBCRYPTO_ERROR_INTERNAL,
        DBCRYPTO_ERROR_INVALID_ARGUMENTS
    };
    class DBCrypto {
         public:
            DBCrypto() : m_connection(NULL), m_init(false) {};
            //user name instead of path?
            DBCrypto(const std::string &path,
                                const RawBuffer &rawPass);
            DBCrypto(const DBCrypto &other) = delete;
            DBCrypto(DBCrypto &&other);

            DBCrypto& operator=(const DBCrypto& ) = delete;
            DBCrypto& operator=(DBCrypto&& other);

            ~DBCrypto();

            bool isInit() {return m_init;};
            DBCryptoReturn saveDBRow(const DBRow &row);
            DBCryptoReturn getDBRow(const Alias &alias, DBRow& row);
            DBCryptoReturn getAliases(DBQueryType dataType, const std::string &label,
                    AliasVector &aliases);
            DBCryptoReturn deleteAlias(const Alias& alias);

         private:
            DB::SqlConnection* m_connection;
            bool m_init;

            void initDatabase();
            bool checkTableExist(const std::string& table);
            DBCryptoReturn getSingleType(DBDataType type, const std::string& label,
                    AliasVector& aliases);

   };
}
#endif //DB_CRYPTO_H
