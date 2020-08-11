
##----------------------------------------------------------------
##
##    テストの設定。
##

Add_Test (NAME  CryptToolsSettingsTest
    COMMAND  $<TARGET_FILE:CryptToolsSettingsTest>
)

##----------------------------------------------------------------
##
##    テストプログラムのビルド。
##

Add_Executable (CryptToolsSettingsTest  CryptToolsSettingsTest.cpp)

