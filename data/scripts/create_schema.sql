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
 * @file        create_schema.sql
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     4.0
 * @brief       DB script to create database schema.
 */


-- create the tables
CREATE TABLE IF NOT EXISTS SCHEMA_INFO(name TEXT PRIMARY KEY NOT NULL,
                                       value TEXT);

CREATE TABLE IF NOT EXISTS NAMES(name TEXT NOT NULL,
                                 label TEXT NOT NULL,
                                 idx INTEGER PRIMARY KEY AUTOINCREMENT,
                                 UNIQUE(name, label));

CREATE TABLE IF NOT EXISTS OBJECTS(exportable INTEGER NOT NULL,
                                   dataType INTEGER NOT NULL,
                                   algorithmType INTEGER NOT NULL,
                                   encryptionScheme INTEGER NOT NULL,
                                   iv BLOB NOT NULL,
                                   dataSize INTEGER NOT NULL,
                                   data BLOB NOT NULL,
                                   tag BLOB NOT NULL,
                                   idx INTEGER NOT NULL,
                                   backendId INTEGER NOT NULL DEFAULT 1,
                                   FOREIGN KEY(idx) REFERENCES NAMES(idx) ON DELETE CASCADE,
                                   PRIMARY KEY(idx, dataType));

CREATE TABLE IF NOT EXISTS KEYS(label TEXT PRIMARY KEY,
                                key BLOB NOT NULL);

CREATE TABLE IF NOT EXISTS PERMISSIONS(permissionLabel TEXT NOT NULL,
                                       permissionMask INTEGER NOT NULL,
                                       idx INTEGER NOT NULL,
                                       FOREIGN KEY(idx) REFERENCES NAMES(idx) ON DELETE CASCADE,
                                       PRIMARY KEY(permissionLabel, idx));


-- create views
CREATE VIEW IF NOT EXISTS [join_name_object_tables] AS
   SELECT N.name, N.label, O.* FROM NAMES AS N
       JOIN OBJECTS AS O ON O.idx=N.idx;

CREATE VIEW IF NOT EXISTS [join_name_permission_tables] AS
   SELECT N.name, N.label, P.permissionMask, P.permissionLabel FROM NAMES AS N
       JOIN PERMISSIONS AS P ON P.idx=N.idx;

CREATE VIEW IF NOT EXISTS [join_all_tables] AS
   SELECT N.*, P.permissionLabel, P.permissionMask, O.dataType FROM NAMES AS N
       JOIN OBJECTS AS O ON O.idx=N.idx
       JOIN PERMISSIONS AS P ON P.idx=N.idx;


-- create indexes
CREATE INDEX IF NOT EXISTS perm_index_idx ON PERMISSIONS(idx);
CREATE INDEX IF NOT EXISTS name_index_idx ON NAMES(idx);

