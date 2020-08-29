//  -*-  coding: utf-8-with-signature;  mode: c++  -*-  //
/*************************************************************************
**                                                                      **
**              ---   The Cryption Library and Tools   ---              **
**                                                                      **
**          Copyright (C), 2020-2020, Takahiro Itou                     **
**          All Rights Reserved.                                        **
**                                                                      **
**          License: (See COPYING and LICENSE files)                    **
**          GNU General Public License (GPL) version 3,                 **
**          or (at your option) any later version.                      **
**                                                                      **
*************************************************************************/

/**
**      An Implementation of Test Case 'AesInterface'.
**
**      @file       Crypts/Tests/AesInterfaceTest.cpp
**/

#include    "AdvancedEncryptionStandardTest.h"


CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AesInterfaceTest  class.
//
/**
**    クラス AdvancedEncryptionStandard の単体テスト。
**/

class  AesInterfaceTest : public  AdvancedEncryptionStandardTest
{
    CPPUNIT_TEST_SUITE(AesInterfaceTest);
    CPPUNIT_TEST(testAdvancedEncryptionStandard);
    CPPUNIT_TEST(testDecryptData);
    CPPUNIT_TEST(testEncryptData);
    CPPUNIT_TEST_SUITE_END();

public:

    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:

    void  testAdvancedEncryptionStandard();
    void  testDecryptData();
    void  testEncryptData();

};

CPPUNIT_TEST_SUITE_REGISTRATION( AesInterfaceTest );

//========================================================================
//
//    Tests.
//

void  AesInterfaceTest::testAdvancedEncryptionStandard()
{
    Testee  aes;

    return;
}

void  AesInterfaceTest::testDecryptData()
{
    Testee  aes;

    BtByte  actual[16];

    //  Test Data # 1.  //
    {
        const   BtByte  ckeys1[16]  = {
            0x2B, 0x7E, 0x15, 0x16,     0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,     0x09, 0xCF, 0x4F, 0x3C
        };
        const   BtByte  source1[16] = {
            0x39, 0x25, 0x84, 0x1D,     0x02, 0xDC, 0x09, 0xFB,
            0xDC, 0x11, 0x85, 0x97,     0x19, 0x6A, 0x0B, 0x32
        };
        const   BtByte  target1[16] = {
            0x32, 0x43, 0xF6, 0xA8,     0x88, 0x5A, 0x30, 0x8D,
            0x31, 0x31, 0x98, 0xA2,     0xE0, 0x37, 0x07, 0x34
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.decryptData(
                        ckeys1, Testee::CRYPT_FLAGS_AES_128,
                        source1, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target1, actual));
    }

    //  Test Data # 2.  //
    {
        const   BtByte  ckeys2[16]  = {
            0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F
        };
        const   BtByte  source2[16] = {
            0x69, 0xC4, 0xE0, 0xD8,     0x6A, 0x7B, 0x04, 0x30,
            0xD8, 0xCD, 0xB7, 0x80,     0x70, 0xB4, 0xC5, 0x5A
        };
        const   BtByte  target2[16] = {
            0x00, 0x11, 0x22, 0x33,     0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,     0xCC, 0xDD, 0xEE, 0xFF
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.decryptData(
                        ckeys2, Testee::CRYPT_FLAGS_AES_128,
                        source2, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target2, actual));
    }

    //  Test Data # 3.  //
    {
        const   BtByte  ckeys3[32]  = {
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00
        };
        const   BtByte  source3[16] = {
            0xDC, 0x95, 0xC0, 0x78,     0xA2, 0x40, 0x89, 0x89,
            0xAD, 0x48, 0xA2, 0x14,     0x92, 0x84, 0x20, 0x87
        };
        const   BtByte  target3[16] = {
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.decryptData(
                        ckeys3, Testee::CRYPT_FLAGS_AES_256,
                        source3, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target3, actual));
    }

    //  Test Data # 4.  //
    {
        const   BtByte  ckeys4[32]  = {
            0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B,     0x1C, 0x1D, 0x1E, 0x1F
        };
        const   BtByte  source4[16] = {
            0x8E, 0xA2, 0xB7, 0xCA,     0x51, 0x67, 0x45, 0xBF,
            0xEA, 0xFC, 0x49, 0x90,     0x4B, 0x49, 0x60, 0x89
        };
        const   BtByte  target4[16] = {
            0x00, 0x11, 0x22, 0x33,     0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,     0xCC, 0xDD, 0xEE, 0xFF
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.decryptData(
                        ckeys4, Testee::CRYPT_FLAGS_AES_256,
                        source4, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target4, actual));
    }

    //  Test Data # 5.  //
    {
        const   BtByte  ckeys5[24]  = {
            0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17
        };
        const   BtByte  source5[16] = {
            0xDD, 0xA9, 0x7C, 0xA4,     0x86, 0x4C, 0xDF, 0xE0,
            0x6E, 0xAF, 0x70, 0xA0,     0xEC, 0x0D, 0x71, 0x91
        };
        const   BtByte  target5[16] = {
            0x00, 0x11, 0x22, 0x33,     0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,     0xCC, 0xDD, 0xEE, 0xFF
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.decryptData(
                        ckeys5, Testee::CRYPT_FLAGS_AES_192,
                        source5, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target5, actual));
    }

    return;
}

void  AesInterfaceTest::testEncryptData()
{
    Testee  aes;

    BtByte  actual[16];

    //  Test Data # 1.  //
    {
        const   BtByte  ckeys1[16]  = {
            0x2B, 0x7E, 0x15, 0x16,     0x28, 0xAE, 0xD2, 0xA6,
            0xAB, 0xF7, 0x15, 0x88,     0x09, 0xCF, 0x4F, 0x3C
        };
        const   BtByte  source1[16] = {
            0x32, 0x43, 0xF6, 0xA8,     0x88, 0x5A, 0x30, 0x8D,
            0x31, 0x31, 0x98, 0xA2,     0xE0, 0x37, 0x07, 0x34
        };
        const   BtByte  target1[16] = {
            0x39, 0x25, 0x84, 0x1D,     0x02, 0xDC, 0x09, 0xFB,
            0xDC, 0x11, 0x85, 0x97,     0x19, 0x6A, 0x0B, 0x32
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.encryptData(
                        ckeys1, Testee::CRYPT_FLAGS_AES_128,
                        source1, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target1, actual));
    }

    //  Test Data # 2.  //
    {
        const   BtByte  ckeys2[16]  = {
            0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F
        };
        const   BtByte  source2[16] = {
            0x00, 0x11, 0x22, 0x33,     0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,     0xCC, 0xDD, 0xEE, 0xFF
        };
        const   BtByte  target2[16] = {
            0x69, 0xC4, 0xE0, 0xD8,     0x6A, 0x7B, 0x04, 0x30,
            0xD8, 0xCD, 0xB7, 0x80,     0x70, 0xB4, 0xC5, 0x5A
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.encryptData(
                        ckeys2, Testee::CRYPT_FLAGS_AES_128,
                        source2, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target2, actual));
    }

    //  Test Data # 3.  //
    {
        const   BtByte  ckeys3[32]  = {
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00
        };
        const   BtByte  source3[16] = {
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00
        };
        const   BtByte  target3[16] = {
            0xDC, 0x95, 0xC0, 0x78,     0xA2, 0x40, 0x89, 0x89,
            0xAD, 0x48, 0xA2, 0x14,     0x92, 0x84, 0x20, 0x87
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.encryptData(
                        ckeys3, Testee::CRYPT_FLAGS_AES_256,
                        source3, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target3, actual));
    }

    //  Test Data # 4.  //
    {
        const   BtByte  ckeys4[32]  = {
            0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B,     0x1C, 0x1D, 0x1E, 0x1F
        };
        const   BtByte  source4[16] = {
            0x00, 0x11, 0x22, 0x33,     0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,     0xCC, 0xDD, 0xEE, 0xFF
        };
        const   BtByte  target4[16] = {
            0x8E, 0xA2, 0xB7, 0xCA,     0x51, 0x67, 0x45, 0xBF,
            0xEA, 0xFC, 0x49, 0x90,     0x4B, 0x49, 0x60, 0x89
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.encryptData(
                        ckeys4, Testee::CRYPT_FLAGS_AES_256,
                        source4, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target4, actual));
    }

    //  Test Data # 5.  //
    {
        const   BtByte  ckeys5[24]  = {
            0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17
        };
        const   BtByte  source5[16] = {
            0x00, 0x11, 0x22, 0x33,     0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,     0xCC, 0xDD, 0xEE, 0xFF
        };
        const   BtByte  target5[16] = {
            0xDD, 0xA9, 0x7C, 0xA4,     0x86, 0x4C, 0xDF, 0xE0,
            0x6E, 0xAF, 0x70, 0xA0,     0xEC, 0x0D, 0x71, 0x91
        };

        CPPUNIT_ASSERT_EQUAL(
                aes.encryptData(
                        ckeys5, Testee::CRYPT_FLAGS_AES_192,
                        source5, actual),
                ERR_SUCCESS);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(target5, actual));
    }

    return;
}

}   //  End of namespace  Crypts
CRYPTTOOLS_NAMESPACE_END

//========================================================================
//
//    エントリポイント。
//

int  main(int argc, char * argv[])
{
    return ( executeCppUnitTests(argc, argv) );
}
