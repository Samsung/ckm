/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Kyungwook Tak <k.tak@samsung.com>
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
 *
 * @file        test_common.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version
 * @brief
 */
#pragma once
#include <string>
#include <ckm/ckm-type.h>

// mirrors the API-defined value
#ifndef AES_GCM_TAG_SIZE
#define AES_GCM_TAG_SIZE 16
#endif

CKM::RawBuffer createDefaultPass();
CKM::RawBuffer createBigBlob(std::size_t size);

const CKM::RawBuffer defaultPass = createDefaultPass();
const std::string pattern =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const std::size_t RAW_PASS_SIZE = 32;
const std::size_t HEX_PASS_SIZE = RAW_PASS_SIZE * 2;


std::string rawToHexString(const CKM::RawBuffer &raw);
