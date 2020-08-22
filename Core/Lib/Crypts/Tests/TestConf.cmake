
##----------------------------------------------------------------
##
##    テストの設定。
##

Add_Test (NAME  AdvancedEncryptionStandardTest
    COMMAND  $<TARGET_FILE:AdvancedEncryptionStandardTest>
)

##----------------------------------------------------------------
##
##    テストプログラムのビルド。
##

Add_Executable (
    AdvancedEncryptionStandardTest
    AdvancedEncryptionStandardTest.cpp
)

