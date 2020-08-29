
##----------------------------------------------------------------
##
##    テストの設定。
##

Add_Test (NAME  AdvancedEncryptionStandardTest
    COMMAND  $<TARGET_FILE:AdvancedEncryptionStandardTest>
)

Add_Test (NAME  AesInterfaceTest
    COMMAND  $<TARGET_FILE:AesInterfaceTest>
)

##----------------------------------------------------------------
##
##    テストプログラムのビルド。
##

Add_Executable (
    AdvancedEncryptionStandardTest
    AdvancedEncryptionStandardTest.cpp
)

Add_Executable (
    AesInterfaceTest
    AesInterfaceTest.cpp
)

