﻿//  -*-  coding: utf-8-with-signature;  mode: c++  -*-  //
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
**      An Implementation of Test Case 'AdvancedEncryptionStandard'.
**
**      @file       Crypts/Tests/AdvancedEncryptionStandardTest.cpp
**/

#include    "TestDriver.h"
#include    "CryptTools/Crypts/AdvancedEncryptionStandard.h"

#include    <vector>

CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AdvancedEncryptionStandardTest  class.
//
/**
**    クラス AdvancedEncryptionStandard の単体テスト。
**/

class  AdvancedEncryptionStandardTest : public  TestFixture
{
    CPPUNIT_TEST_SUITE(AdvancedEncryptionStandardTest);
    CPPUNIT_TEST(testAdvancedEncryptionStandard);
    CPPUNIT_TEST(testDecryptData);
    CPPUNIT_TEST(testEncryptData);
    CPPUNIT_TEST(testGenerateRoundKeys1);
    CPPUNIT_TEST(testGenerateRoundKeys2);
    CPPUNIT_TEST(testGenerateRoundKeys3);
    CPPUNIT_TEST(testGenerateRoundKeys4);
    CPPUNIT_TEST(testReadSBoxTable);
    CPPUNIT_TEST(testRunDecryptSteps1);
    CPPUNIT_TEST(testRunDecryptSteps2);
    CPPUNIT_TEST(testRunDecryptSteps3);
    CPPUNIT_TEST(testRunDecryptSteps4);
    CPPUNIT_TEST(testRunEncryptSteps1);
    CPPUNIT_TEST(testRunEncryptSteps2);
    CPPUNIT_TEST(testRunEncryptSteps3);
    CPPUNIT_TEST(testRunEncryptSteps4);
    CPPUNIT_TEST_SUITE_END();

public:
    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:
    typedef     AdvancedEncryptionStandard      Testee;
    typedef     Testee::CryptRoundKeys          CryptRoundKeys;

    template  <size_t  N>
    static  const   int
    checkRoundKeys(
            const  Testee::WordKey  (&vExpect)[N],
            const  CryptRoundKeys   & vActual);

    template  <typename  T,  size_t  N>
    static  const   int
    compareArray(
            const   T   (&vExpect)[N],
            const   T   (&vActual)[N]);

private:
    void  testAdvancedEncryptionStandard();
    void  testDecryptData();
    void  testEncryptData();
    void  testGenerateRoundKeys1();
    void  testGenerateRoundKeys2();
    void  testGenerateRoundKeys3();
    void  testGenerateRoundKeys4();
    void  testReadSBoxTable();
    void  testRunDecryptSteps1();
    void  testRunDecryptSteps2();
    void  testRunDecryptSteps3();
    void  testRunDecryptSteps4();
    void  testRunEncryptSteps1();
    void  testRunEncryptSteps2();
    void  testRunEncryptSteps3();
    void  testRunEncryptSteps4();
};

CPPUNIT_TEST_SUITE_REGISTRATION( AdvancedEncryptionStandardTest );

//========================================================================
//
//    Helper Functions.
//

template <size_t  N>
const   int
AdvancedEncryptionStandardTest::checkRoundKeys(
        const  Testee::WordKey  (&vExpect)[N],
        const  CryptRoundKeys   & vActual)
{
    int     counter = 0;

    CPPUNIT_ASSERT_EQUAL(vActual.size(), N);

    for ( size_t i = 0; i < N; ++ i ) {
        for ( int j = 0; j < Testee::NUM_WORDS_IN_ROUND_KEY; ++ j ){
            if ( vExpect[i][j] != vActual[i][j] ) {
                ++ counter;
            }
        }
    }

    return ( counter );
}

template  <typename  T,  size_t  N>
const   int
AdvancedEncryptionStandardTest::compareArray(
        const   T   (&vExpect)[N],
        const   T   (&vActual)[N])
{
    int     counter = 0;
    for ( size_t i = 0; i < N; ++ i ) {
        if ( vExpect[i] != vActual[i] ) {
            ++ counter;
        }
    }

    return ( counter );
}

//========================================================================
//
//    Tests.
//

void  AdvancedEncryptionStandardTest::testAdvancedEncryptionStandard()
{
    Testee  aes;

    return;
}

void  AdvancedEncryptionStandardTest::testDecryptData()
{
    Testee  aes;

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
    BtByte  actual[16];

    CPPUNIT_ASSERT_EQUAL(
            aes.decryptData(
                    ckeys1, Testee::CRYPT_FLAGS_AES_128, source1, actual),
            ERR_SUCCESS);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(target1, actual));

    return;
}

void  AdvancedEncryptionStandardTest::testEncryptData()
{
    Testee  aes;

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
    BtByte  actual[16];

    CPPUNIT_ASSERT_EQUAL(
            aes.encryptData(
                    ckeys1, Testee::CRYPT_FLAGS_AES_128, source1, actual),
            ERR_SUCCESS);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(target1, actual));

    return;
}

void  AdvancedEncryptionStandardTest::testGenerateRoundKeys1()
{
    typedef     Testee::CryptRoundKeys  CryptRoundKeys;

    Testee          aes;
    CryptRoundKeys  w;

    const   BtByte  keys[16] = {
        0x2B, 0x7E, 0x15, 0x16,     0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,     0x09, 0xCF, 0x4F, 0x3C
    };

    const   Testee::WordKey     expect[] = {
        { 0x16157E2B, 0xA6D2AE28, 0x8815F7AB, 0x3C4FCF09 },
        { 0x17FEFAA0, 0xB12C5488, 0x3939A323, 0x05766C2A },
        { 0xF295C2F2, 0x43B9967A, 0x7A803559, 0x7FF65973 },
        { 0x7D47803D, 0x3EFE1647, 0x447E231E, 0x3B887A6D },
        { 0x41A544EF, 0x7F5B52A8, 0x3B2571B6, 0x00AD0BDB },
        { 0xF8C6D1D4, 0x879D837C, 0xBCB8F2CA, 0xBC15F911 },
        { 0x7AA3886D, 0xFD3E0B11, 0x4186F9DB, 0xFD9300CA },
        { 0x0EF7544E, 0xF3C95F5F, 0xB24FA684, 0x4FDCA64E },
        { 0x2173D2EA, 0xD2BA8DB5, 0x60F52B31, 0x2F298D7F },
        { 0xF36677AC, 0x21DCFA19, 0x4129D128, 0x6E005C57 },
        { 0xA8F914D0, 0x8925EEC9, 0xC80C3FE1, 0xA60C63B6 }
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(keys, 4, 10, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));
}

void  AdvancedEncryptionStandardTest::testGenerateRoundKeys2()
{
    typedef     Testee::CryptRoundKeys  CryptRoundKeys;

    Testee          aes;
    CryptRoundKeys  w;

    const   BtByte  keys[16] = {
        0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F
    };

    const   Testee::WordKey     expect[] = {
        { 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C },
        { 0xFD74AAD6, 0xFA72AFD2, 0xF178A6DA, 0xFE76ABD6 },
        { 0x0BCF92B6, 0xF1BD3D64, 0x00C59BBE, 0xFEB33068 },
        { 0x4E74FFB6, 0xBFC9C2D2, 0xBF0C596C, 0x41BF6904 },
        { 0xBCF7F747, 0x033E3595, 0xBC326CF9, 0xFD8D05FD },
        { 0xE8A3AA3C, 0xEB9D9FA9, 0x57AFF350, 0xAA22F6AD },
        { 0x7D0F395E, 0x9692A6F7, 0xC13D55A7, 0x6B1FA30A },
        { 0x1A70F914, 0x8CE25FE3, 0x4DDF0A44, 0x26C0A94E },
        { 0x35874347, 0xB9651CA4, 0xF4BA16E0, 0xD27ABFAE },
        { 0xD1329954, 0x685785F0, 0x9CED9310, 0x4E972CBE },
        { 0x7F1D1113, 0x174A94E3, 0x8BA707F3, 0xC5302B4D }
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(keys, 4, 10, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));
}

void  AdvancedEncryptionStandardTest::testGenerateRoundKeys3()
{
    typedef     Testee::CryptRoundKeys  CryptRoundKeys;

    Testee          aes;
    CryptRoundKeys  w;

    const   BtByte  keys[32] = {
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00
    };

    const   Testee::WordKey     expect[] = {
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
        { 0x63636362, 0x63636362, 0x63636362, 0x63636362 },
        { 0xFBFBFBAA, 0xFBFBFBAA, 0xFBFBFBAA, 0xFBFBFBAA },
        { 0xCF6C6C6F, 0xAC0F0F0D, 0xCF6C6C6F, 0xAC0F0F0D },
        { 0x6A8D8D7D, 0x917676D7, 0x6A8D8D7D, 0x917676D7 },
        { 0xC1ED5453, 0x6DE25B5E, 0xA28E3731, 0x0E81383C },
        { 0xC1818A96, 0x50F7FC41, 0x3A7A713C, 0xAB0C07EB },
        { 0x288FAA9E, 0x456DF1C0, 0xE7E3C6F1, 0xE962FECD },
        { 0xDF2B312B, 0x8FDCCD6A, 0xB5A6BC56, 0x1EAABBBD },
        { 0x52FD0664, 0x1790F7A4, 0xF0733155, 0x1911CF98 },
        { 0x0BA9BB6D, 0x84757607, 0x31D3CA51, 0x2F7971EC },
        { 0x9CE8B0E7, 0x8B784743, 0x7B0B7616, 0x621AB98E },
        { 0xA10BED74, 0x257E9B73, 0x14AD5122, 0x3BD420CE },
        { 0x170AF810, 0x9C72BF53, 0xE779C945, 0x856370CB }
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(keys, 8, 14, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));
}

void  AdvancedEncryptionStandardTest::testGenerateRoundKeys4()
{
    typedef     Testee::CryptRoundKeys  CryptRoundKeys;

    Testee          aes;
    CryptRoundKeys  w;

    const   BtByte  keys[32] = {
        0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,     0x1C, 0x1D, 0x1E, 0x1F
    };

    const   Testee::WordKey     expect[] = {
        { 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C },
        { 0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C },
        { 0x9FC273A5, 0x98C476A1, 0x93CE7FA9, 0x9CC072A5 },
        { 0xCDA85116, 0xDABE4402, 0xC1A45D1A, 0xDEBA4006 },
        { 0xF0DF87AE, 0x681BF10F, 0xFBD58EA6, 0x6715FC03 },
        { 0x48F1E16D, 0x924FA56F, 0x53EBF875, 0x8D51B873 },
        { 0x7F8256C6, 0x1799A7C9, 0xEC4C296F, 0x8B59D56C },
        { 0x753AE23D, 0xE7754752, 0xB49EBF27, 0x39CF0754 },
        { 0x5F90DC0B, 0x48097BC2, 0xA44552AD, 0x2F1C87C1 },
        { 0x60A6F545, 0x87D3B217, 0x334D0D30, 0x0A820A64 },
        { 0x1CF7CF7C, 0x54FEB4BE, 0xF0BBE613, 0xDFA761D2 },
        { 0xFEFA1AF0, 0x7929A8E7, 0x4A64A5D7, 0x40E6AFB3 },
        { 0x71FE4125, 0x2500F59B, 0xD5BB1388, 0x0A1C725A },
        { 0x99665A4E, 0xE04FF2A9, 0xAA2B577E, 0xEACDF8CD },
        { 0xCC79FC24, 0xE97909BF, 0x3CC21A37, 0x36DE686D }
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(keys, 8, 14, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));
}

void  AdvancedEncryptionStandardTest::testReadSBoxTable()
{
    BtWord  tableInvs[256] = {};
    BtWord  tablePows[6][52] = {};
    BtWord  tmpPoly[6] = {
        0x00000001, 0x00000001,
        0x00000003, 0x000000f6,
        0x00000005, 0x00000052
    };

    for ( int idx = 0; idx < 256; ++ idx ) {
        tableInvs[idx]  = 0;
    }
    for ( int j = 0; j < 6; ++ j ) {
        BtWord  curPoly = tmpPoly[j];
        for ( int i = 0; i < 52; ++ i ) {
            tablePows[j][i] = (curPoly & 0xFF);
            curPoly <<= 1;
            if ( curPoly & 0x00000100 ) {
                curPoly ^= 0x0000011B;
            }
        }
    }
    for ( int j = 0; j < 6; ++ j ) {
        for ( int i = 0; i < 52; ++ i ) {
            BtByte  src = tablePows[j][i];
            BtByte  trg = tablePows[j ^ 1][51 - i];
            tableInvs[src]  = trg;
        }
    }

    for ( int i = 0; i <= 255; ++ i ) {
        const   BtByte  val     = static_cast<BtByte>(i);
        const   int     actual  = Testee::readSBoxTable(val);

        BtByte  tmp = val;
        tmp = tableInvs[tmp];

        const  int  b0  = (tmp     ) & 0x01;
        const  int  b1  = (tmp >> 1) & 0x01;
        const  int  b2  = (tmp >> 2) & 0x01;
        const  int  b3  = (tmp >> 3) & 0x01;
        const  int  b4  = (tmp >> 4) & 0x01;
        const  int  b5  = (tmp >> 5) & 0x01;
        const  int  b6  = (tmp >> 6) & 0x01;
        const  int  b7  = (tmp >> 7) & 0x01;

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

void  AdvancedEncryptionStandardTest::testRunDecryptSteps1()
{
    Testee          aes;

    CryptRoundKeys  rKeys;
    Testee::TState  state   = {
        0x1D842539, 0xFB09DC02, 0x978511DC, 0x320B6A19
    };
    const   BtByte  baseKey[16] = {
        0x2B, 0x7E, 0x15, 0x16,     0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,     0x09, 0xCF, 0x4F, 0x3C
    };
    const   BtWord  expect[11][4][4] = {
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(baseKey, 4, 10, rKeys));

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), rKeys.size());

    int     i = 10;
    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    for ( i = 10 - 1; i >= 1; -- i ) {
        Testee::runTestInvShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

        Testee::runTestInvSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w));

        Testee::runTestInvMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w) );
    }

    Testee::runTestInvShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

    Testee::runTestInvSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    return;
}

void  AdvancedEncryptionStandardTest::testRunDecryptSteps2()
{
    Testee          aes;

    CryptRoundKeys  rKeys;
    Testee::TState  state   = {
        0xD8E0C469, 0x30047B6A, 0x80B7CDD8, 0x5AC5B470
    };
    const   BtByte  baseKey[16] = {
        0x2B, 0x7E, 0x15, 0x16,     0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,     0x09, 0xCF, 0x4F, 0x3C
    };
    const   BtWord  expect[11][4][4] = {
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(baseKey, 4, 10, rKeys));

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), rKeys.size());

    int     i = 10;
    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    for ( i = 10 - 1; i >= 1; -- i ) {
        Testee::runTestInvShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

        Testee::runTestInvSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w));

        Testee::runTestInvMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w) );
    }

    Testee::runTestInvShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

    Testee::runTestInvSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    return;
}

void  AdvancedEncryptionStandardTest::testRunDecryptSteps3()
{
    Testee          aes;

    CryptRoundKeys  rKeys;
    Testee::TState  state   = {
        0x78C095DC, 0x898940A2, 0x14A248AD, 0x87208492
    };
    const   BtByte  baseKey[32] = {
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00
    };
    const   BtWord  expect[11][4][4] = {
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(baseKey, 4, 10, rKeys));

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), rKeys.size());

    int     i = 10;
    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    for ( i = 10 - 1; i >= 1; -- i ) {
        Testee::runTestInvShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

        Testee::runTestInvSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w));

        Testee::runTestInvMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w) );
    }

    Testee::runTestInvShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

    Testee::runTestInvSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    return;
}

void  AdvancedEncryptionStandardTest::testRunDecryptSteps4()
{
    Testee          aes;

    CryptRoundKeys  rKeys;
    Testee::TState  state   = {
        0xCAB7A28E, 0xBF456751, 0x9049FCEA, 0x8960494B
    };
    const   BtByte  baseKey[32] = {
        0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,     0x1C, 0x1D, 0x1E, 0x1F
    };
    const   BtWord  expect[11][4][4] = {
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(baseKey, 4, 10, rKeys));

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), rKeys.size());

    int     i = 10;
    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    for ( i = 10 - 1; i >= 1; -- i ) {
        Testee::runTestInvShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

        Testee::runTestInvSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w));

        Testee::runTestInvMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w) );
    }

    Testee::runTestInvShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

    Testee::runTestInvSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    return;
}

void  AdvancedEncryptionStandardTest::testRunEncryptSteps1()
{
    Testee          aes;

    CryptRoundKeys  rKeys;
    Testee::TState  state   = {
        0xA8F64332, 0x8D305A88, 0xA2983131, 0x340737E0
    };

    const   BtByte  baseKey[16] = {
        0x2B, 0x7E, 0x15, 0x16,     0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,     0x09, 0xCF, 0x4F, 0x3C
    };

    const   BtWord  expect[11][4][4] = {
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(baseKey, 4, 10, rKeys));

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), rKeys.size());

    int     i = 0;
    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    for ( i = 1; i < 10; ++ i ) {
        Testee::runTestSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

        Testee::runTestShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

        Testee::runTestMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w) );

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));
    }

    Testee::runTestSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    Testee::runTestShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    return;
}

void  AdvancedEncryptionStandardTest::testRunEncryptSteps2()
{
    Testee          aes;

    CryptRoundKeys  rKeys;
    Testee::TState  state   = {
        0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC
    };

    const   BtByte  baseKey[16] = {
        0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F
    };

    const   BtWord  expect[11][4][4] = {
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(baseKey, 4, 10, rKeys));

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), rKeys.size());

    int     i = 0;
    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    for ( i = 1; i < 10; ++ i ) {
        Testee::runTestSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

        Testee::runTestShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

        Testee::runTestMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w) );

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));
    }

    Testee::runTestSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    Testee::runTestShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    return;
}

void  AdvancedEncryptionStandardTest::testRunEncryptSteps3()
{
    Testee          aes;

    CryptRoundKeys  rKeys;
    Testee::TState  state   = {
        0xA8F64332, 0x8D305A88, 0xA2983131, 0x340737E0
    };

    const   BtByte  baseKey[32] = {
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00
    };

    const   BtWord  expect[11][4][4] = {
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(baseKey, 4, 10, rKeys));

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), rKeys.size());

    int     i = 0;
    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    for ( i = 1; i < 10; ++ i ) {
        Testee::runTestSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

        Testee::runTestShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

        Testee::runTestMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w) );

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));
    }

    Testee::runTestSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    Testee::runTestShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    return;
}

void  AdvancedEncryptionStandardTest::testRunEncryptSteps4()
{
    Testee          aes;

    CryptRoundKeys  rKeys;
    Testee::TState  state   = {
        0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC
    };

    const   BtByte  baseKey[32] = {
        0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,     0x1C, 0x1D, 0x1E, 0x1F
    };

    const   BtWord  expect[11][4][4] = {
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(baseKey, 4, 10, rKeys));

    CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(11), rKeys.size());

    int     i = 0;
    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

    for ( i = 1; i < 10; ++ i ) {
        Testee::runTestSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

        Testee::runTestShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

        Testee::runTestMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w) );

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));
    }

    Testee::runTestSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    Testee::runTestShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][3], state.w));

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
