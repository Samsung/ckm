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
 * @file        ckmc-type-converter.h
 * @author      Dongsun Lee(ds73.lee@samsung.com)
 * @version     1.0
 * @brief       new and free methods for the struct of CAPI
 */

#ifndef CKMC_TYPE_CONVERTER_H_
#define CKMC_TYPE_CONVERTER_H_

#include <ckm/ckm-error.h>
#include <ckmc/ckmc-error.h>
#include <ckmc/ckmc-type.h>

#ifdef __cplusplus
extern "C" {
#endif

int to_ckmc_error(int ckm_error);
int to_ckm_error(int ckmc_error);
ckmc_ocsp_status_e to_ckmc_ocsp_status(int ckm_ocsp_status);
int access_to_permission_mask(ckmc_access_right_e ar, int & permissionMask);

#ifdef __cplusplus
}
#endif

#endif /* CKMC_TYPE_CONVERTER_H_ */
