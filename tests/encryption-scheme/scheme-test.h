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

#include <string>

#include <ckm/ckm-control.h>
#include <ckm/ckm-manager.h>

#include <data-type.h>

struct Item {
    Item() : type(CKM::DataType::DB_FIRST){}
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

class SchemeTest {
public:
    SchemeTest();
    ~SchemeTest();

    void FillDb();

private:
    void SwitchToUser();
    void SwitchToRoot();

    CKM::ControlShPtr m_control;
    CKM::ManagerShPtr m_mgr;
    std::string m_origLabel;
    bool m_userChanged;
};
