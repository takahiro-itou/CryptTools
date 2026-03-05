
##----------------------------------------------------------------
##
##    モジュールの設定。
##

Set (MODULE_DIR_NAME       "Crypts")
Set (MODULE_OUTPUT_NAME    "Crypts")
Set (MODULE_TITLE          "Crypts")

Set (INCLIB_SOURCE_DIR     "${INCLUDE_SOURCE_DIR}/${MODULE_DIR_NAME}")
Set (INCLIB_BINARY_DIR     "${INCLUDE_BINARY_DIR}/${MODULE_DIR_NAME}")

##----------------------------------------------------------------
##
##    ソースファイルとヘッダファイルのリスト。
##

Set (LIBRARY_SOURCE_FILES
        AdvancedEncryptionStandard.cpp
)

Set (INCLIB_HEADER_FILES
        ${INCLIB_SOURCE_DIR}/AdvancedEncryptionStandard.h
)

Set (MODULE_NEEDS_LIBRARIES
        ${PROJECT_NAME}-${LIBRARIES_TARGET_PREFIX}Common
)

##----------------------------------------------------------------
##
##    ビルドとインストールの設定。
##

Include (${COMMON_CMAKE_DIR}/BuildLibraryCommon.cmake)

##----------------------------------------------------------------
##
##    テストの設定。
##

Add_SubDirectory (Tests)

