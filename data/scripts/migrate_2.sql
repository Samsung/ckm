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
DROP INDEX perm_index_idx;


-- create new structure
CREATE TABLE SCHEMA_INFO(name TEXT PRIMARY KEY NOT NULL,
                         value TEXT);
ALTER TABLE NAME_TABLE RENAME TO NAMES;
-- need to create OBJECT table from scratch,
-- as SQLite does not support "ALTER COLUMN"
-- (REFERENCES NAME_TABLE --> NAMES)
CREATE TABLE OBJECTS(exportable INTEGER NOT NULL,
                     dataType INTEGER NOT NULL,
                     algorithmType INTEGER NOT NULL,
                     encryptionScheme INTEGER NOT NULL,
                     iv BLOB NOT NULL,
                     dataSize INTEGER NOT NULL,
                     data BLOB NOT NULL,
                     tag BLOB NOT NULL,
                     idx INTEGER NOT NULL,
                     FOREIGN KEY(idx) REFERENCES NAMES(idx) ON DELETE CASCADE,
                     PRIMARY KEY(idx, dataType));
ALTER TABLE KEY_TABLE RENAME TO KEYS;
CREATE TABLE PERMISSIONS(permissionLabel TEXT NOT NULL,
                         permissionMask INTEGER NOT NULL,
                         idx INTEGER NOT NULL,
                         FOREIGN KEY(idx) REFERENCES NAMES(idx) ON DELETE CASCADE,
                         PRIMARY KEY(permissionLabel, idx));
CREATE INDEX perm_index_idx ON PERMISSIONS(idx);
CREATE VIEW [join_name_object_tables] AS
        SELECT N.name, N.label, O.* FROM NAMES AS N
            JOIN OBJECTS AS O ON O.idx=N.idx;
CREATE VIEW [join_name_permission_tables] AS
        SELECT N.name, N.label, P.permissionMask, P.permissionLabel FROM NAMES AS N
            JOIN PERMISSIONS AS P ON P.idx=N.idx;
CREATE VIEW [join_all_tables] AS
        SELECT N.*, P.permissionLabel, P.permissionMask, O.dataType FROM NAMES AS N
            JOIN OBJECTS AS O ON O.idx=N.idx
            JOIN PERMISSIONS AS P ON P.idx=N.idx;


-- move data
INSERT INTO OBJECTS SELECT * FROM OBJECT_TABLE;
INSERT INTO PERMISSIONS(permissionLabel, permissionMask, idx) SELECT label, 1, idx FROM PERMISSION_TABLE WHERE accessFlags='R';
INSERT INTO PERMISSIONS(permissionLabel, permissionMask, idx) SELECT label, 3, idx FROM PERMISSION_TABLE WHERE accessFlags='RD';
INSERT INTO PERMISSIONS(permissionLabel, permissionMask, idx) SELECT label, 3, idx FROM NAMES;


-- cleanup
DROP TABLE OBJECT_TABLE;
DROP TABLE PERMISSION_TABLE;

