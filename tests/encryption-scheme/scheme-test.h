/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       scheme-test.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <ckm/ckm-control.h>
#include <ckm/ckm-manager.h>

#include <data-type.h>

namespace CKM {
namespace DB {
class Crypto;
} // DB
} // CKM

struct Item {
    Item() {}
    Item(const CKM::Alias& alias,
         const CKM::DataType::Type type,
         const CKM::Policy& policy)
    : alias(alias), type(type), policy(policy)
    {
    }

    CKM::Alias alias;
    CKM::DataType::Type type;
    CKM::Policy policy;
};

typedef std::vector<Item> Items;

struct ItemFilter {
    ItemFilter() :
        typeFrom(CKM::DataType::DB_FIRST),
        typeTo(CKM::DataType::DB_LAST),
        exportableOnly(false),
        noPassword(false)
    {}

    explicit ItemFilter(CKM::DataType::Type type) :
        typeFrom(type),
        typeTo(type),
        exportableOnly(false),
        noPassword(false)
    {}

    ItemFilter(CKM::DataType::Type typeFrom, CKM::DataType::Type typeTo) :
        typeFrom(typeFrom),
        typeTo(typeTo),
        exportableOnly(false),
        noPassword(false)
    {}

    bool Matches(const Item& item) const {
        if(item.type < typeFrom || item.type > typeTo)
            return false;
        if(exportableOnly && !item.policy.extractable)
            return false;
        if(noPassword && !item.policy.password.empty())
            return false;
        return true;
    }

    CKM::DataType::Type typeFrom;
    CKM::DataType::Type typeTo;
    bool exportableOnly;
    bool noPassword;
};

class SchemeTest {
public:
    SchemeTest();
    ~SchemeTest();

    void RemoveUserData();
    void FillDb();
    void ReadAll(bool useWrongPass = false);
    void SignVerify();
    void EncryptDecrypt();
    void CreateChain();
    void RemoveAll();
    size_t CountObjects();
    void RestoreDb();
    void CheckSchemeVersion(const ItemFilter& filter, int version);

private:
    void SwitchToUser();
    void SwitchToRoot();
    void EnableDirectDbAccess();
    void SignVerifyItem(const Item& itemPrv, const Item& itemPub);
    void EncryptDecryptItem(const Item& item);
    void EncryptDecryptItem(const Item& itemPrv, const Item& itemPub);
    void CreateChainItem(const Item& leaf, const Items& certs);

    CKM::ControlShPtr m_control;
    CKM::ManagerShPtr m_mgr;
    std::string m_origLabel;
    bool m_userChanged;

    std::unique_ptr<CKM::DB::Crypto> m_db;
    bool m_directAccessEnabled;
};
