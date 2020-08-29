
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

Add_Test (NAME  AesTableDataTest
    COMMAND  $<TARGET_FILE:AesTableDataTest>
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

Add_Executable (
    AesTableDataTest
    AesTableDataTest.cpp
)

