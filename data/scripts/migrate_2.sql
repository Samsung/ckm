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
 * @file        migrate_2.sql
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       DB migration script from schema version 2 to schema version 3.
 */


-- isolate old data
ALTER TABLE PERMISSION_TABLE RENAME TO OLD_PERMISSION_TABLE;
DROP INDEX perm_index_idx;


-- create new structure
CREATE TABLE SCHEMA_INFO(name TEXT PRIMARY KEY NOT NULL,
                         value TEXT);
CREATE TABLE PERMISSION_TABLE(permissionLabel TEXT NOT NULL,
                              permissionMask INTEGER NOT NULL,
                              idx INTEGER NOT NULL,
                              FOREIGN KEY(idx) REFERENCES NAME_TABLE(idx) ON DELETE CASCADE,
                              PRIMARY KEY(permissionLabel, idx));
CREATE INDEX perm_index_idx ON PERMISSION_TABLE(idx);
CREATE VIEW [join_name_object_tables] AS
        SELECT N.name, N.label, O.* FROM NAME_TABLE AS N
            JOIN OBJECT_TABLE AS O ON O.idx=N.idx;
CREATE VIEW [join_name_permission_tables] AS
        SELECT N.name, N.label, P.permissionMask, P.permissionLabel FROM NAME_TABLE AS N
            JOIN PERMISSION_TABLE AS P ON P.idx=N.idx;
CREATE VIEW [join_all_tables] AS
        SELECT N.*, P.permissionLabel, P.permissionMask, O.dataType FROM NAME_TABLE AS N
            JOIN OBJECT_TABLE AS O ON O.idx=N.idx
            JOIN PERMISSION_TABLE AS P ON P.idx=N.idx;


-- move data
INSERT INTO PERMISSION_TABLE(permissionLabel, permissionMask, idx) SELECT label, 1, idx FROM OLD_PERMISSION_TABLE WHERE accessFlags='R';
INSERT INTO PERMISSION_TABLE(permissionLabel, permissionMask, idx) SELECT label, 3, idx FROM OLD_PERMISSION_TABLE WHERE accessFlags='RD';
INSERT INTO PERMISSION_TABLE(permissionLabel, permissionMask, idx) SELECT label, 3, idx FROM NAME_TABLE;


-- cleanup
DROP TABLE OLD_PERMISSION_TABLE;
