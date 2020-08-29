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
**      An Implementation of Test Case 'AesTableData'.
**
**      @file       Crypts/Tests/AesTableDataTest.cpp
**/

#include    "AdvancedEncryptionStandardTest.h"


CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AesTableDataTest  class.
//
/**
**    クラス AdvancedEncryptionStandard の単体テスト。
**/

class  AesTableDataTest : public  AdvancedEncryptionStandardTest
{
    CPPUNIT_TEST_SUITE(AesTableDataTest);
    CPPUNIT_TEST(testReadInvSBoxTable);
    CPPUNIT_TEST(testReadMixColConvTable);
    CPPUNIT_TEST(testReadSBoxTable);
    CPPUNIT_TEST_SUITE_END();

public:

    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:

    void  testReadInvSBoxTable();
    void  testReadMixColConvTable();
    void  testReadSBoxTable();

};

CPPUNIT_TEST_SUITE_REGISTRATION( AesTableDataTest );

//========================================================================
//
//    Tests.
//

void  AesTableDataTest::testReadInvSBoxTable()
{
    BtWord  tableInvs[256] = {};

    generatePolyInvTable(tableInvs);

    for ( int i = 0; i <= 255; ++ i ) {
        const   BtByte  val     = static_cast<BtByte>(i);
        const   int     actual  = readInvSBoxTable(val);

        const  int  b7  = (val >> 7) & 0x01;
        const  int  b6  = (val >> 6) & 0x01;
        const  int  b5  = (val >> 5) & 0x01;
        const  int  b4  = (val >> 4) & 0x01;
        const  int  b3  = (val >> 3) & 0x01;
        const  int  b2  = (val >> 2) & 0x01;
        const  int  b1  = (val >> 1) & 0x01;
        const  int  b0  = (val     ) & 0x01;

        const  int  c7  = (b6 ^ b4 ^ b1) ^ 0;
        const  int  c6  = (b5 ^ b3 ^ b0) ^ 0;
        const  int  c5  = (b4 ^ b2 ^ b7) ^ 0;
        const  int  c4  = (b3 ^ b1 ^ b6) ^ 0;
        const  int  c3  = (b2 ^ b0 ^ b5) ^ 0;
        const  int  c2  = (b1 ^ b7 ^ b4) ^ 1;
        const  int  c1  = (b0 ^ b6 ^ b3) ^ 0;
        const  int  c0  = (b7 ^ b5 ^ b2) ^ 1;

        const  BtByte  tmp  = (c0 & 1)
            | ((c1 & 1) << 1)
            | ((c2 & 1) << 2)
            | ((c3 & 1) << 3)
            | ((c4 & 1) << 4)
            | ((c5 & 1) << 5)
            | ((c6 & 1) << 6)
            | ((c7 & 1) << 7);
        const  int  expect  = tableInvs[tmp];
        CPPUNIT_ASSERT_EQUAL(expect, actual);
    }
}

void  AesTableDataTest::testReadMixColConvTable()
{
    for ( int i = 0; i < 255; ++ i ) {
        const   BtByte  y1  = static_cast<BtByte>(i);
        const   BtWord  y2  = readMixColConvTable(y1, 0);
        const   BtWord  y3  = readMixColConvTable(y1, 1);
        const   BtWord  yE  = readMixColConvTable(y1, 2);
        const   BtWord  y9  = readMixColConvTable(y1, 3);
        const   BtWord  yD  = readMixColConvTable(y1, 4);
        const   BtWord  yB  = readMixColConvTable(y1, 5);

        const   BtWord  x2  = (y1 << 1) ^ (y1 & 0x80 ? 0x11B : 0x00);
        const   BtWord  x4  = (x2 << 1) ^ (x2 & 0x80 ? 0x11B : 0x00);
        const   BtWord  x8  = (x4 << 1) ^ (x4 & 0x80 ? 0x11B : 0x00);

        const   BtWord  x3  = (x2 ^ y1)      & 0xFF;
        const   BtWord  xE  = (x8 ^ x4 ^ x2) & 0xFF;
        const   BtWord  x9  = (x8 ^ y1)      & 0xFF;
        const   BtWord  xD  = (x8 ^ x4 ^ y1) & 0xFF;
        const   BtWord  xB  = (x8 ^ x2 ^ y1) & 0xFF;

        CPPUNIT_ASSERT_EQUAL(x2, y2);
        CPPUNIT_ASSERT_EQUAL(x3, y3);
        CPPUNIT_ASSERT_EQUAL(xE, yE);
        CPPUNIT_ASSERT_EQUAL(x9, y9);
        CPPUNIT_ASSERT_EQUAL(xD, yD);
        CPPUNIT_ASSERT_EQUAL(xB, yB);
    }

    return;
}

void  AesTableDataTest::testReadSBoxTable()
{
    BtWord  tableInvs[256] = {};

    generatePolyInvTable(tableInvs);

    for ( int i = 0; i <= 255; ++ i ) {
        const   BtByte  val     = static_cast<BtByte>(i);
        const   int     actual  = readSBoxTable(val);

        BtByte  tmp = val;
        tmp = tableInvs[tmp];

        const  int  b7  = (tmp >> 7) & 0x01;
        const  int  b6  = (tmp >> 6) & 0x01;
        const  int  b5  = (tmp >> 5) & 0x01;
        const  int  b4  = (tmp >> 4) & 0x01;
        const  int  b3  = (tmp >> 3) & 0x01;
        const  int  b2  = (tmp >> 2) & 0x01;
        const  int  b1  = (tmp >> 1) & 0x01;
        const  int  b0  = (tmp     ) & 0x01;

        const  int  c7  = (b7 ^ b6 ^ b5 ^ b4 ^ b3) ^ 0;
        const  int  c6  = (b6 ^ b5 ^ b4 ^ b3 ^ b2) ^ 1;
        const  int  c5  = (b5 ^ b4 ^ b3 ^ b2 ^ b1) ^ 1;
        const  int  c4  = (b4 ^ b3 ^ b2 ^ b1 ^ b0) ^ 0;
        const  int  c3  = (b3 ^ b2 ^ b1 ^ b0 ^ b7) ^ 0;
        const  int  c2  = (b2 ^ b1 ^ b0 ^ b7 ^ b6) ^ 0;
        const  int  c1  = (b1 ^ b0 ^ b7 ^ b6 ^ b5) ^ 1;
        const  int  c0  = (b0 ^ b7 ^ b6 ^ b5 ^ b4) ^ 1;

        const  int  expect  = (c0 & 1)
            | ((c1 & 1) << 1)
            | ((c2 & 1) << 2)
            | ((c3 & 1) << 3)
            | ((c4 & 1) << 4)
            | ((c5 & 1) << 5)
            | ((c6 & 1) << 6)
            | ((c7 & 1) << 7);
        CPPUNIT_ASSERT_EQUAL(expect, actual);
    }
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
