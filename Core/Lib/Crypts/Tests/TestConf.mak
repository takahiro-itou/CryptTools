
##
##    List of Tests.
##

EXTRATESTS              =
TESTS                   =  \
        AdvancedEncryptionStandardTest  \
        AesInterfaceTest                \
        AesSteps01Test                  \
        AesSteps02Test                  \
        AesSteps03Test                  \
        AesSteps04Test                  \
        AesSteps05Test                  \
        AesTableDataTest                \
        ${EXTRATESTS}
##
##    Test Configurations.
##

TARGET_TESTEE_LIBRARY       +=  -lctCrypts

DIST_NOINST_DATA_FILES      +=
DIST_NOINST_HEADER_FILES    +=  \
        AdvancedEncryptionStandardTest.h
EXTRA_TEST_DRIVERS          +=
LIBRARY_TEST_DRIVERS        +=
SOURCE_TEST_DRIVERS         +=

##
##    Compile and Link Options.
##

TEST_CPPFLAGS_COMMON        +=
TEST_LDFLAGS_COMMON         +=

##
##    Test Programs.
##

AdvancedEncryptionStandardTest_SOURCES  =  \
        AdvancedEncryptionStandardTest.cpp

AesInterfaceTest_SOURCES    =  AesInterfaceTest.cpp
AesSteps01Test_SOURCES      =  AesSteps01Test.cpp
AesSteps02Test_SOURCES      =  AesSteps02Test.cpp
AesSteps03Test_SOURCES      =  AesSteps03Test.cpp
AesSteps04Test_SOURCES      =  AesSteps04Test.cpp
AesSteps05Test_SOURCES      =  AesSteps05Test.cpp
AesTableDataTest_SOURCES    =  AesTableDataTest.cpp

