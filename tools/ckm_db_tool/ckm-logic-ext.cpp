/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file       ckm-logic-ext.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <ckm-logic-ext.h>
#include <db-crypto-ext.h>

namespace CKM {

DB::SqlConnection::Output CKMLogicExt::Execute(uid_t user, const std::string& cmd) {
    if(user < 5000 && !m_systemDbUnlocked) {
        if(CKM_API_SUCCESS != unlockSystemDB())
            ThrowErr(Exc::DatabaseLocked, "can not unlock system database");
        m_systemDbUnlocked = true;
    }

    DB::SqlConnection::Output output;

    /*
     * We need to access to DB::Crypto::m_connection to call Execute() on it. We don't want to mess
     * with DB::Crypto too much so adding a friend and extending public interface was not an option.
     * That's why we need a derived class DB::CryptoExt. m_userDataMap must be left unchanged after
     * this operation but DB::Crypto can't be copied. According to C++ standard static casting
     * DB::Crypto pointer to DB::CryptoExt pointer is UB. Therefore DB::Crypto is temporarily moved
     * into DB::CryptoExt and moved back to m_userDataMap after the call to Execute().
     */
    DB::CryptoExt db(std::move(m_userDataMap[user].database));
    try {
        output = db.Execute(cmd);
        m_userDataMap[user].database = std::move(*static_cast<DB::Crypto*>(&db));
        return output;
    } catch (const DB::SqlConnection::Exception::Base& e) {
        m_userDataMap[user].database = std::move(*static_cast<DB::Crypto*>(&db));
        throw;
    }
}

} // namespace CKM


