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
 * @file        migrate_1.sql
 * @author      Maciej Karpiuk (m.karpiuk2@samsung.com)
 * @version     1.0
 * @brief       DB migration script from schema version 1 to schema version 2.
 */


-- isolate old data
ALTER TABLE PERMISSION_TABLE RENAME TO OLD_PERMISSION_TABLE;
DROP INDEX perm_index_idx;


-- create new structure
CREATE TABLE NAME_TABLE(name TEXT NOT NULL,
                        label TEXT NOT NULL,
                        idx INTEGER PRIMARY KEY AUTOINCREMENT,
                        UNIQUE(name, label));
CREATE INDEX name_index_idx ON NAME_TABLE(idx);
CREATE TABLE OBJECT_TABLE(exportable INTEGER NOT NULL,
                          dataType INTEGER NOT NULL,
                          algorithmType INTEGER NOT NULL,
                          encryptionScheme INTEGER NOT NULL,
                          iv BLOB NOT NULL,
                          dataSize INTEGER NOT NULL,
                          data BLOB NOT NULL,
                          tag BLOB NOT NULL,
                          idx INTEGER NOT NULL,
                          FOREIGN KEY(idx) REFERENCES NAME_TABLE(idx) ON DELETE CASCADE,
                          PRIMARY KEY(idx, dataType));
CREATE TABLE PERMISSION_TABLE(label TEXT NOT NULL,
                              accessFlags TEXT NOT NULL,
                              idx INTEGER NOT NULL,
                              FOREIGN KEY(idx) REFERENCES NAME_TABLE(idx) ON DELETE CASCADE,
                              PRIMARY KEY(label, idx));
CREATE INDEX perm_index_idx ON PERMISSION_TABLE(idx);


-- move data
INSERT INTO NAME_TABLE(name, label, idx) SELECT name, label, idx FROM CKM_TABLE;
INSERT INTO OBJECT_TABLE(exportable, dataType, algorithmType, encryptionScheme,
                         iv, dataSize, data, tag, idx)
                SELECT exportable, dataType, algorithmType, encryptionScheme, iv,
                       dataSize, data, tag, idx FROM CKM_TABLE;
INSERT INTO PERMISSION_TABLE(label, accessFlags, idx) SELECT label, accessFlags, idx FROM OLD_PERMISSION_TABLE;


-- cleanup
DROP TABLE OLD_PERMISSION_TABLE;
DROP TABLE CKM_TABLE;
