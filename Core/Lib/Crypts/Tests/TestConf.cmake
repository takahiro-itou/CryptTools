
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

Add_Test (NAME  AesSteps01Test
    COMMAND  $<TARGET_FILE:AesSteps01Test>
)

Add_Test (NAME  AesSteps02Test
    COMMAND  $<TARGET_FILE:AesSteps02Test>
)

Add_Test (NAME  AesSteps03Test
    COMMAND  $<TARGET_FILE:AesSteps03Test>
)

Add_Test (NAME  AesSteps04Test
    COMMAND  $<TARGET_FILE:AesSteps04Test>
)

Add_Test (NAME  AesSteps05Test
    COMMAND  $<TARGET_FILE:AesSteps05Test>
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
    AesSteps01Test
    AesSteps01Test.cpp
)

Add_Executable (
    AesSteps02Test
    AesSteps02Test.cpp
)

Add_Executable (
    AesSteps03Test
    AesSteps03Test.cpp
)

Add_Executable (
    AesSteps04Test
    AesSteps04Test.cpp
)

Add_Executable (
    AesSteps05Test
    AesSteps05Test.cpp
)

Add_Executable (
    AesTableDataTest
    AesTableDataTest.cpp
)

