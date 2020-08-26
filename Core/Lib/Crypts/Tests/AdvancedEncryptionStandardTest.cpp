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

    template  <int ROUNDS, int KEYLEN, size_t STLEN=4>
    inline  void
    runDecryptSteps(
            const   BtByte  (&baseKey)[KEYLEN * 4],
            const   BtWord  (&expect)[ROUNDS+1][5][STLEN],
            Testee::TState  & state);

    template  <int ROUNDS, int KEYLEN, size_t STLEN=4>
    inline  void
    runEncryptSteps(
            const   BtByte  (&baseKey)[KEYLEN * 4],
            const   BtWord  (&expect)[ROUNDS+1][5][STLEN],
            Testee::TState  & state);

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

template  <int ROUNDS, int KEYLEN, size_t STLEN>
inline  void
AdvancedEncryptionStandardTest::runDecryptSteps(
            const   BtByte  (&baseKey)[KEYLEN * 4],
            const   BtWord  (&expect)[ROUNDS+1][5][STLEN],
            Testee::TState  & state)
{
    CryptRoundKeys  rKeys;

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(
                    baseKey, KEYLEN, ROUNDS, rKeys)
    );
    CPPUNIT_ASSERT_EQUAL(
            static_cast<size_t>(ROUNDS + 1), rKeys.size()
    );

    int     i = ROUNDS;

    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));

    for ( int j = 0; j < KEYLEN; ++ j ) {
        CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
    }

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    for ( i = ROUNDS - 1; i >= 1; -- i ) {
        Testee::runTestInvShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

        Testee::runTestInvSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));

        for ( int j = 0; j < KEYLEN; ++ j ) {
            CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
        }

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w));

        Testee::runTestInvMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w) );
    }

    Testee::runTestInvShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

    Testee::runTestInvSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));

    for ( int j = 0; j < KEYLEN; ++ j ) {
        CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
    }

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    return;
}

template  <int ROUNDS, int KEYLEN, size_t STLEN>
inline  void
AdvancedEncryptionStandardTest::runEncryptSteps(
        const   BtByte  (&baseKey)[KEYLEN * 4],
        const   BtWord  (&expect)[ROUNDS+1][5][STLEN],
        Testee::TState  & state)
{
    CryptRoundKeys  rKeys;

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            Testee::generateRoundKeys(
                    baseKey, KEYLEN, ROUNDS, rKeys)
    );
    CPPUNIT_ASSERT_EQUAL(
            static_cast<size_t>(ROUNDS + 1), rKeys.size()
    );

    int     i = 0;

    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    for ( int j = 0; j < KEYLEN; ++ j ) {
        CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
    }

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));

    for ( i = 1; i < ROUNDS; ++ i ) {
        Testee::runTestSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

        Testee::runTestShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

        Testee::runTestMixColumns(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][2], state.w) );

        for ( int j = 0; j < KEYLEN; ++ j ) {
            CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
        }

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));
    }

    Testee::runTestSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    Testee::runTestShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    for ( int j = 0; j < KEYLEN; ++ j ) {
        CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
    }

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));

    return;
}

//========================================================================
//
//    Test Data.
//

//----------------------------------------------------------------
//    Test Data # 1

const   BtByte  td1BaseKey[16]  = {
    0x2B, 0x7E, 0x15, 0x16,     0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88,     0x09, 0xCF, 0x4F, 0x3C
};

const   BtWord  td1Expect[11][5][4] = {
};

//----------------------------------------------------------------
//    Test Data # 2

const   BtByte  td2BaseKey[16] = {
    0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F
};

const   BtWord  td2Expect[11][5][4] = {
    {
        { 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C },
        { 0x30201000, 0x70605040, 0xB0A09080, 0xF0E0D0C0 }
    }, {
        { 0x04B7CA63, 0x51D05309, 0xE7E060CD, 0x8CE170BA },
        { 0x8CE05363, 0x04E16009, 0x51B770CD, 0xE7D0CABA },
        { 0x1564725F, 0x92BCF557, 0x293BBEF7, 0x1AF9B91D },
        { 0xFD74AAD6, 0xFA72AFD2, 0xF178A6DA, 0xFE76ABD6 },
        { 0xE810D889, 0x68CE5A85, 0xD843182D, 0xE48F12CB }
    }, {
        { 0x9BCA61A7, 0x458BBE97, 0x611AADD8, 0x6973C91F },
        { 0x691ABEA7, 0x9B73AD97, 0x45CAC9D8, 0x618B611F },
        { 0x849687FF, 0x516AD831, 0xFA515164, 0x09D03A77 },
        { 0x0BCF92B6, 0xF1BD3D64, 0x00C59BBE, 0xFEB33068 },
        { 0x8F591549, 0xA0D7E555, 0xFA94CADA, 0xF7630A1F }
    }, {
        { 0x73CB593B, 0xE00ED9FC, 0x2D227457, 0x68FB67C0 },
        { 0x6822D93B, 0x73FB74FC, 0xE0CB6757, 0x2D0E59C0 },
        { 0x661E9C4C, 0x76F071F7, 0x8E863F2C, 0x56F24D53 },
        { 0x4E74FFB6, 0xBFC9C2D2, 0xBF0C596C, 0x41BF6904 },
        { 0x286A63FA, 0xC939B325, 0x318A6640, 0x174D2457 }
    }, {
        { 0x3402FB2D, 0xDD126D3F, 0xC77E3309, 0xF0E3365B },
        { 0xF07E6D2D, 0x34E3333F, 0xDD023609, 0xC712FB5B },
        { 0x9FB78563, 0xF98D53FC, 0x8E47BE97, 0x91D64775 },
        { 0xBCF7F747, 0x033E3595, 0xBC326CF9, 0xFD8D05FD },
        { 0x23407224, 0xFAB36669, 0x3275D26E, 0x6C5B4288 }
    }, {
        { 0x26094036, 0x2D6D33F9, 0x239DB59F, 0x50392CC4 },
        { 0x509D3336, 0x2639B5F9, 0x2D092C9F, 0x236D40C4 },
        { 0x54D4BCF4, 0xD054E532, 0xC5D6F175, 0x3C3BD01D },
        { 0xE8A3AA3C, 0xEB9D9FA9, 0x57AFF350, 0xAA22F6AD },
        { 0xBC7716C8, 0x3BC97A9B, 0x92790225, 0x961926B0 }
    }, {
        { 0x65F547E8, 0xE2DDDA14, 0x4FB6773F, 0x90D4F7E7 },
        { 0x90B6DAE8, 0x65D47714, 0xE2F5F73F, 0x4FDD47E7 },
        { 0x74EE1698, 0x557FF800, 0x9C042C6B, 0x36D05A8E },
        { 0x7D0F395E, 0x9692A6F7, 0xC13D55A7, 0x6B1FA30A },
        { 0x09E12FC6, 0xC3ED5EF7, 0x5D3979CC, 0x5DCFF984 }
    }, {
        { 0x01F815B4, 0x2E555868, 0x4C12B64B, 0x4C8A995F },
        { 0x4C1258B4, 0x018AB668, 0x2EF8994B, 0x4C55155F },
        { 0x151C7EC5, 0x86D29B9A, 0xE04B5FF0, 0x3934C698 },
        { 0x1A70F914, 0x8CE25FE3, 0x4DDF0A44, 0x26C0A94E },
        { 0x0F6C87D1, 0x0A30C479, 0xAD9455B4, 0x1FF46FD6 }
    }, {
        { 0x7650173E, 0x67041CB6, 0x9522FC8D, 0xC0BFA8F6 },
        { 0xC0221C3E, 0x76BFFCB6, 0x6750A88D, 0x950417F6 },
        { 0xE73DA0BA, 0x6EB5F9A1, 0xBA2C51D5, 0x234D415F },
        { 0x35874347, 0xB9651CA4, 0xF4BA16E0, 0xD27ABFAE },
        { 0xD2BAE3FD, 0xD7D0E505, 0x4E964735, 0xF137FEF1 }
    }, {
        { 0xB5F41154, 0x0E70D96B, 0x2F90A096, 0xA19ABBA1 },
        { 0xA190D954, 0xB59AA06B, 0x0EF4BB96, 0x2F7011A1 },
        { 0xEC4EF7E9, 0xF6203002, 0xF2CCF21B, 0xC7213C35 },
        { 0xD1329954, 0x685785F0, 0x9CED9310, 0x4E972CBE },
        { 0x3D7C6EBD, 0x9E77B5F2, 0x6E21610B, 0x89B6108B }
    }, {
        { 0x27109F7A, 0x0BF5D589, 0x9FFDEF2B, 0xA74ECA3D },
        { 0xA7FDD57A, 0x274EEF89, 0x0B10CA2B, 0x9FF59F3D },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x7F1D1113, 0x174A94E3, 0x8BA707F3, 0xC5302B4D },
        { 0xD8E0C469, 0x30047B6A, 0x80B7CDD8, 0x5AC5B470 }
    }
};

//----------------------------------------------------------------
//    Test Data # 3

const   BtByte  td3BaseKey[32] = {
    0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00, 0x00
};

const   BtWord  td3Expect[15][5][4] = {
    {
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000 }
    }, {
        { 0x63636363, 0x63636363, 0x63636363, 0x63636363 },
        { 0x63636363, 0x63636363, 0x63636363, 0x63636363 },
        { 0x63636363, 0x63636363, 0x63636363, 0x63636363 },
        { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
        { 0x63636363, 0x63636363, 0x63636363, 0x63636363 }
    }, {
        { 0xFBFBFBFB, 0xFBFBFBFB, 0xFBFBFBFB, 0xFBFBFBFB },
        { 0xFBFBFBFB, 0xFBFBFBFB, 0xFBFBFBFB, 0xFBFBFBFB },
        { 0xFBFBFBFB, 0xFBFBFBFB, 0xFBFBFBFB, 0xFBFBFBFB },
        { 0x63636362, 0x63636362, 0x63636362, 0x63636362 },
        { 0x98989899, 0x98989899, 0x98989899, 0x98989899 }
    }, {
        { 0x464646EE, 0x464646EE, 0x464646EE, 0x464646EE },
        { 0x464646EE, 0x464646EE, 0x464646EE, 0x464646EE },
        { 0xA5EEEE0D, 0xA5EEEE0D, 0xA5EEEE0D, 0xA5EEEE0D },
        { 0xFBFBFBAA, 0xFBFBFBAA, 0xFBFBFBAA, 0xFBFBFBAA },
        { 0x5E1515A7, 0x5E1515A7, 0x5E1515A7, 0x5E1515A7 }
    }, {
        { 0x5859595C, 0x5859595C, 0x5859595C, 0x5859595C },
        { 0x5859595C, 0x5859595C, 0x5859595C, 0x5859595C },
        { 0x545F5D52, 0x545F5D52, 0x545F5D52, 0x545F5D52 },
        { 0xCF6C6C6F, 0xAC0F0F0D, 0xCF6C6C6F, 0xAC0F0F0D },
        { 0x9B33313D, 0xF850525F, 0x9B33313D, 0xF850525F }
    }, {
        { 0x14C3C727, 0x415300CF, 0x14C3C727, 0x415300CF },
        { 0x41C30027, 0x1453C7CF, 0x41C30027, 0x1453C7CF },
        { 0x287938CC, 0xF692BB90, 0x287938CC, 0xF692BB90 },
        { 0x6A8D8D7D, 0x917676D7, 0x6A8D8D7D, 0x917676D7 },
        { 0x42F4B5B1, 0x67E4CD47, 0x42F4B5B1, 0x67E4CD47 }
    }, {
        { 0x2CBFD5C8, 0x8569BDA0, 0x2CBFD5C8, 0x8569BDA0 },
        { 0x85BFBDC8, 0x2C69D5A0, 0x85BFBDC8, 0x2C69D5A0 },
        { 0x5084F66D, 0x1FD3867A, 0x5084F66D, 0x1FD3867A },
        { 0xC1ED5453, 0x6DE25B5E, 0xA28E3731, 0x0E81383C },
        { 0x9169A23E, 0x7231DD24, 0xF20AC15C, 0x1152BE46 }
    }, {
        { 0x81F93AB2, 0x40C7C136, 0x8967784A, 0x8200AE5A },
        { 0x8267C1B2, 0x81007836, 0x40F9AE4A, 0x89C73A5A },
        { 0x742000C2, 0x3BD64765, 0x09CD5DC4, 0x1A75F5B4 },
        { 0xC1818A96, 0x50F7FC41, 0x3A7A713C, 0xAB0C07EB },
        { 0xB5A18A54, 0x6B21BB24, 0x33B72CF8, 0xB179F25F }
    }, {
        { 0xD5327E20, 0x7FFDEA36, 0xC3A97141, 0xC8B689CF },
        { 0xC8A9EA20, 0xD5B67136, 0x7F328941, 0xC3FD7ECF },
        { 0xA8C0C704, 0x2C54C09C, 0x862D614F, 0x540EEC39 },
        { 0x288FAA9E, 0x456DF1C0, 0xE7E3C6F1, 0xE962FECD },
        { 0x804F6D9A, 0x6939315C, 0x61CEA76E, 0xBD6C12F4 }
    }, {
        { 0xCD843CB8, 0xF912C74A, 0xEF8B5CAE, 0x7A50C9BF },
        { 0x7A8BC7B8, 0xCD505C4A, 0xF984C9AE, 0xEF123CBF },
        { 0x6BFCD1C8, 0x53FACFED, 0x4D64497A, 0x318D1EDC },
        { 0xDF2B312B, 0x8FDCCD6A, 0xB5A6BC56, 0x1EAABBBD },
        { 0xB4D7E0E3, 0xDC260287, 0xF8C2F52C, 0x2F27A561 }
    }, {
        { 0x8D0EE111, 0x86F77717, 0x4125E671, 0x15CC06EF },
        { 0x15257711, 0x8DCCE617, 0x860E0671, 0x41F7E1EF },
        { 0x4B13858B, 0x12FE025E, 0x8CFAE960, 0xBE38754B },
        { 0x52FD0664, 0x1790F7A4, 0xF0733155, 0x1911CF98 },
        { 0x19EE83EF, 0x056EF5FA, 0x7C89D835, 0xA729BAD3 }
    }, {
        { 0xD428ECDF, 0x6B9FE62D, 0x10A76196, 0x5CA5F466 },
        { 0x5CA7E6DF, 0xD4A5612D, 0x6B28F496, 0x109FEC66 },
        { 0x8388A66F, 0x007ACF88, 0xAB8F7673, 0xF99F0F6C },
        { 0x0BA9BB6D, 0x84757607, 0x31D3CA51, 0x2F7971EC },
        { 0x88211D02, 0x840FB98F, 0x9A5CBC22, 0xD6E67E80 }
    }, {
        { 0xC4FDA477, 0x5F765673, 0xB84A6593, 0xF68EF3CD },
        { 0xF64A5677, 0xC48E6573, 0x5FFDF393, 0xB876A4CD },
        { 0x72B4F3A8, 0xED46F403, 0x1E602D91, 0xF556BCB8 },
        { 0x9CE8B0E7, 0x8B784743, 0x7B0B7616, 0x621AB98E },
        { 0xEE5C434F, 0x663EB340, 0x656B5B87, 0x974C0536 }
    }, {
        { 0x284A1A84, 0x33B26D09, 0x4D7F3917, 0x88296B05 },
        { 0x887F6D84, 0x28293909, 0x334A6B17, 0x4DB21A05 },
        { 0x8E945753, 0x5B1A2858, 0x7EBD2CEA, 0x3DB7B1DB },
        { 0xA10BED74, 0x257E9B73, 0x14AD5122, 0x3BD420CE },
        { 0x2F9FBA27, 0x7E64B32B, 0x6A107DC8, 0x06639115 },
    }, {
        { 0x15DBF4CC, 0xF3436DF1, 0x02CAFFE8, 0x6FFB8159 },
        { 0x6FCA6DCC, 0x15FBFFF1, 0xF3DB81E8, 0x0243F459 },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x170AF810, 0x9C72BF53, 0xE779C945, 0x856370CB },
        { 0x78C095DC, 0x898940A2, 0x14A248AD, 0x87208492 }
    }
};

//----------------------------------------------------------------
//    Test Data # 4

const   BtByte  td4BaseKey[32] = {
    0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B,     0x1C, 0x1D, 0x1E, 0x1F
};

const   BtWord  td4Expect[15][5][4] = {
    {
        { 0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C },
        { 0x30201000, 0x70605040, 0xB0A09080, 0xF0E0D0C0 }
    }, {
        { 0x04B7CA63, 0x51D05309, 0xE7E060CD, 0x8CE170BA },
        { 0x8CE05363, 0x04E16009, 0x51B770CD, 0xE7D0CABA },
        { 0x1564725F, 0x92BCF557, 0x293BBEF7, 0x1AF9B91D },
        { 0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C },
        { 0x0676634F, 0x85AAE043, 0x3221A7EF, 0x05E7A401 }
    }, {
        { 0x6F38FB84, 0x97ACE11A, 0x23FD5CDF, 0x6B94497C },
        { 0x6BFDE184, 0x6F945C1A, 0x973849DF, 0x23ACFB7C },
        { 0x5D392ABD, 0x38C46A2B, 0x3E4492D1, 0x95A15D61 },
        { 0x9FC273A5, 0x98C476A1, 0x93CE7FA9, 0x9CC072A5 },
        { 0xC2FB5918, 0xA0001C8A, 0xAD8AED78, 0x09612FC4 }
    }, {
        { 0x250FCBAD, 0xE0639C7E, 0x957E55BC, 0x01EF151C },
        { 0x017E9CAD, 0x25EF557E, 0xE00F15BC, 0x9563CB1C },
        { 0x0CCE0D81, 0x7281DBC9, 0x1E8C67B3, 0xBDB5A188 },
        { 0xCDA85116, 0xDABE4402, 0xC1A45D1A, 0xDEBA4006 },
        { 0xC1665C97, 0xA83F9FCB, 0xDF283AA9, 0x630FE18E }
    }, {
        { 0x78334A88, 0xC275DB1F, 0x9E3480D3, 0xFB76F819 },
        { 0xFB34DB88, 0x7876801F, 0xC233F8D3, 0x9E754A19 },
        { 0x812D82B2, 0x27FBE6AB, 0x3A10AF5F, 0x33008C07 },
        { 0xF0DF87AE, 0x681BF10F, 0xFBD58EA6, 0x6715FC03 },
        { 0x71F2051C, 0x4FE017A4, 0xC1C521F9, 0x54157004 }
    }, {
        { 0xA3896B9C, 0x84E1F049, 0x78A6FD99, 0x205951F2 },
        { 0x20A6F09C, 0xA359FD49, 0x84895199, 0x78E16BF2 },
        { 0xA95BB6AE, 0x22F8E074, 0x7B563FD7, 0x77C864DB },
        { 0x48F1E16D, 0x924FA56F, 0x53EBF875, 0x8D51B873 },
        { 0xE1AA57C3, 0xB0B7451B, 0x28BDC7A2, 0xFA99DCA8 }
    }, {
        { 0xF8AC5B2E, 0xE7A96EAF, 0x347AC63A, 0x2DEE86C2 },
        { 0x2D7A6E2E, 0xF8EEC6AF, 0xE7AC863A, 0x34A95BC2 },
        { 0x3CC351B9, 0x29BDE902, 0xB1CD25AE, 0xC78CA0EF },
        { 0x7F8256C6, 0x1799A7C9, 0xEC4C296F, 0x8B59D56C },
        { 0x4341077F, 0x3E244ECB, 0x5D810CC1, 0x4CD57583 }
    }, {
        { 0x1A83C5D2, 0xB2362F1F, 0x4C0CFE78, 0x29039DEC },
        { 0x290C2FD2, 0x1A03FE1F, 0xB2839D78, 0x4C36C5EC },
        { 0x1C9EB1EB, 0xE8C9E73E, 0xE935757D, 0x44916BED },
        { 0x753AE23D, 0xE7754752, 0xB49EBF27, 0x39CF0754 },
        { 0x69A453D6, 0x0FBCA06C, 0x5DABCA5A, 0x7D5E6CB9 }
    }, {
        { 0xF949EDF6, 0x7665E050, 0x4C6274BE, 0xFF585056 },
        { 0xFF62E0F6, 0xF9587450, 0x764950BE, 0x4C65ED56 },
        { 0x66C87451, 0x3584A99D, 0x2CE6B3A8, 0xEAA574A9 },
        { 0x5F90DC0B, 0x48097BC2, 0xA44552AD, 0x2F1C87C1 },
        { 0x3958A85A, 0x7D8DD25F, 0x88A3E105, 0xC5B9F368 }
    }, {
        { 0x126AC2BE, 0xFF5DB5CF, 0xC40AF86B, 0xA6560D45 },
        { 0xA60AB5BE, 0x1256F8CF, 0xFF6A0D6B, 0xC45DC245 },
        { 0x31EE770F, 0xC0ADCCD2, 0x3FA83054, 0xC36AF94E },
        { 0x60A6F545, 0x87D3B217, 0x334D0D30, 0x0A820A64 },
        { 0x5148824A, 0x477E7EC5, 0x0CE53D64, 0xC9E8F32A }
    }, {
        { 0xD15213D6, 0xA0F3F3A6, 0xFED92743, 0xDD9B0DE5 },
        { 0xDDD9F3D6, 0xD19B27A6, 0xA0520D43, 0xFEF313E5 },
        { 0xEAF086BD, 0xF4C48F74, 0xC1110F63, 0x331233E9 },
        { 0x1CF7CF7C, 0x54FEB4BE, 0xF0BBE613, 0xDFA761D2 },
        { 0xF60749C1, 0xA03A3BCA, 0x31AAE970, 0xECB5523B }
    }, {
        { 0x42C53B78, 0xE080E274, 0xC7AC1E51, 0xCED500E2 },
        { 0xCEACE278, 0x42D51E74, 0xE0C50051, 0xC7803BE2 },
        { 0x419086AF, 0xD31D6E5D, 0xEDFBE587, 0x1390C8D5 },
        { 0xFEFA1AF0, 0x7929A8E7, 0x4A64A5D7, 0x40E6AFB3 },
        { 0xBF6A9C5F, 0xAA34C6BA, 0xA79F4050, 0x53766766 }
    }, {
        { 0x0802DECF, 0xAC18B4F4, 0x5CDB0953, 0xED388533 },
        { 0xEDDBB4CF, 0x083809F4, 0xAC028553, 0x5C18DE33 },
        { 0xE4FA2774, 0x2695A6D8, 0x313DE89C, 0x2B39E05B },
        { 0x71FE4125, 0x2500F59B, 0xD5BB1388, 0x0A1C725A },
        { 0x95046651, 0x03955343, 0xE486FB14, 0x21259201 }
    }, {
        { 0x2AF233D1, 0x7B2AED1A, 0x69440FFA, 0xFD3F4F7C },
        { 0xFD44EDD1, 0x2A3F0F1A, 0x7BF24FFA, 0x692A337C },
        { 0x20A8212C, 0x4A156F30, 0x5EC712B7, 0x4FA00DEE },
        { 0x99665A4E, 0xE04FF2A9, 0xAA2B577E, 0xEACDF8CD },
        { 0xB9CE7B62, 0xAA5A9D99, 0xF4EC45C9, 0xA56DF523 }
    }, {
        { 0x568B21AA, 0xACBE5EEE, 0xBFCE6EDD, 0x063CE626 },
        { 0x06CE5EAA, 0x563C6EEE, 0xAC8BE6DD, 0xBFBE2126 },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xCC79FC24, 0xE97909BF, 0x3CC21A37, 0x36DE686D },
        { 0xCAB7A28E, 0xBF456751, 0x9049FCEA, 0x8960494B }
    }
};

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

    Testee::TState  state   = {
        0x1D842539, 0xFB09DC02, 0x978511DC, 0x320B6A19
    };

    runDecryptSteps<10, 4>(td1BaseKey, td1Expect, state);

    return;
}

void  AdvancedEncryptionStandardTest::testRunDecryptSteps2()
{
    Testee          aes;

    Testee::TState  state   = {
        0xD8E0C469, 0x30047B6A, 0x80B7CDD8, 0x5AC5B470
    };

    runDecryptSteps<10, 4>(td2BaseKey, td2Expect, state);

    return;
}

void  AdvancedEncryptionStandardTest::testRunDecryptSteps3()
{
    Testee          aes;

    Testee::TState  state   = {
        0x78C095DC, 0x898940A2, 0x14A248AD, 0x87208492
    };

    runDecryptSteps<14, 8>(td3BaseKey, td3Expect, state);

    return;
}

void  AdvancedEncryptionStandardTest::testRunDecryptSteps4()
{
    Testee          aes;

    Testee::TState  state   = {
        0xCAB7A28E, 0xBF456751, 0x9049FCEA, 0x8960494B
    };

    runDecryptSteps<14, 8>(td4BaseKey, td4Expect, state);

    return;
}

void  AdvancedEncryptionStandardTest::testRunEncryptSteps1()
{
    Testee          aes;

    Testee::TState  state   = {
        0xA8F64332, 0x8D305A88, 0xA2983131, 0x340737E0
    };

    runEncryptSteps<10, 4>(td1BaseKey, td1Expect, state);

    return;
}

void  AdvancedEncryptionStandardTest::testRunEncryptSteps2()
{
    Testee          aes;

    Testee::TState  state   = {
        0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC
    };

    runEncryptSteps<10, 4>(td2BaseKey, td2Expect, state);

    return;
}

void  AdvancedEncryptionStandardTest::testRunEncryptSteps3()
{
    Testee          aes;

    Testee::TState  state   = {
        0xA8F64332, 0x8D305A88, 0xA2983131, 0x340737E0
    };

    runEncryptSteps<14, 8>(td3BaseKey, td3Expect, state);

    return;
}

void  AdvancedEncryptionStandardTest::testRunEncryptSteps4()
{
    Testee          aes;

    Testee::TState  state   = {
        0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC
    };

    runEncryptSteps<14, 8>(td4BaseKey, td4Expect, state);

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
