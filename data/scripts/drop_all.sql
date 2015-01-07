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
 *
 *
 * @file        drop_all.sql
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       DB script to drop all current and historical objects.
 */


-- drop tables
-- SQLite does not provide DROP ALL TABLES construction.
-- the SQLite-way is to remove the whole database file,
-- which would require expensive changes to the service code
-- (re-establishing the DB connection).
DROP TABLE IF EXISTS SCHEMA_INFO;
DROP TABLE IF EXISTS CKM_TABLE;
DROP TABLE IF EXISTS NAME_TABLE;
DROP TABLE IF EXISTS KEY_TABLE;
DROP TABLE IF EXISTS OBJECT_TABLE;
DROP TABLE IF EXISTS PERMISSION_TABLE;
DROP TABLE IF EXISTS OLD_PERMISSION_TABLE;


-- drop views
DROP VIEW IF EXISTS [join_name_object_tables];
DROP VIEW IF EXISTS [join_name_permission_tables];
DROP VIEW IF EXISTS [join_all_tables];

