# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author      Barlomiej Grzelewski (b.grzelewski@samsung.com)
# @author      Zofia Abramowska (z.abramowska@samsung.com)
# @brief
#

CONFIGURE_FILE(key-manager.pc.in key-manager.pc @ONLY)

INSTALL(FILES
    ${CMAKE_BINARY_DIR}/build/key-manager/key-manager.pc
    DESTINATION
    ${LIB_INSTALL_DIR}/pkgconfig
    )
