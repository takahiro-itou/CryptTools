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
**      An Implementation of Test Case 'AesSteps03'.
**
**      @file       Crypts/Tests/AesSteps03Test.cpp
**/

#include    "AdvancedEncryptionStandardTest.h"


CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AesSteps03Test  class.
//
/**
**    クラス AdvancedEncryptionStandard の単体テスト。
**/

class  AesSteps03Test : public  AdvancedEncryptionStandardTest
{
    CPPUNIT_TEST_SUITE(AesSteps03Test);
    CPPUNIT_TEST(testGenerateRoundKeys3);
    CPPUNIT_TEST(testRunDecryptSteps3);
    CPPUNIT_TEST(testRunEncryptSteps3);
    CPPUNIT_TEST_SUITE_END();

public:

    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:

    void  testGenerateRoundKeys3();
    void  testRunDecryptSteps3();
    void  testRunEncryptSteps3();

};

CPPUNIT_TEST_SUITE_REGISTRATION( AesSteps03Test );

//========================================================================
//
//    Test Data.
//

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
        { 0x804F6D9A, 0x6939315C, 0x61CEA7BE, 0xBD6C12F4 }
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

//========================================================================
//
//    Tests.
//

void  AesSteps03Test::testGenerateRoundKeys3()
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
            generateRoundKeys(keys, 8, 14, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));

    return;
}

void  AesSteps03Test::testRunDecryptSteps3()
{
    Testee          aes;

    Testee::TState  state   = {
        0x78C095DC, 0x898940A2, 0x14A248AD, 0x87208492
    };

    runDecryptSteps<14, 8>(td3BaseKey, td3Expect, state);

    return;
}

void  AesSteps03Test::testRunEncryptSteps3()
{
    Testee          aes;

    Testee::TState  state   = {
        0x00000000, 0x00000000, 0x00000000, 0x00000000
    };

    runEncryptSteps<14, 8>(td3BaseKey, td3Expect, state);

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
