/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 * @file        ckmc-error.cpp
 * @author      Yuseok Jeon(yuseok.jeon@samsung.com)
 * @version     1.0
 * @brief       This file contains the conversion method to C from C++ about how to get error string.
 */

#include <ckmc/ckmc-error.h>
#include <ckm/ckm-type.h>
#include <ckmc/ckmc-type.h>
#include <ckmc-type-converter.h>

KEY_MANAGER_CAPI
const char * ckmc_error_to_string(int error) {
	return CKM::ErrorToString(to_ckm_error(error));
}
