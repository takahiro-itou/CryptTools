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
**      An Implementation of Test Case 'AesSteps02'.
**
**      @file       Crypts/Tests/AesSteps02Test.cpp
**/

#include    "AdvancedEncryptionStandardTest.h"


CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AesSteps02Test  class.
//
/**
**    クラス AdvancedEncryptionStandard の単体テスト。
**/

class  AesSteps02Test : public  AdvancedEncryptionStandardTest
{
    CPPUNIT_TEST_SUITE(AesSteps02Test);
    CPPUNIT_TEST(testGenerateRoundKeys2);
    CPPUNIT_TEST(testRunDecryptSteps2);
    CPPUNIT_TEST(testRunEncryptSteps2);
    CPPUNIT_TEST_SUITE_END();

public:

    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:

    void  testGenerateRoundKeys2();
    void  testRunDecryptSteps2();
    void  testRunEncryptSteps2();

};

CPPUNIT_TEST_SUITE_REGISTRATION( AesSteps02Test );

//========================================================================
//
//    Test Data.
//

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

//========================================================================
//
//    Tests.
//


void  AesSteps02Test::testGenerateRoundKeys2()
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
            generateRoundKeys(keys, 4, 10, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));

    return;
}

void  AesSteps02Test::testRunDecryptSteps2()
{
    Testee          aes;

    Testee::TState  state   = {
        0xD8E0C469, 0x30047B6A, 0x80B7CDD8, 0x5AC5B470
    };

    runDecryptSteps<10, 4>(td2BaseKey, td2Expect, state);

    return;
}

void  AesSteps02Test::testRunEncryptSteps2()
{
    Testee          aes;

    Testee::TState  state   = {
        0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC
    };

    runEncryptSteps<10, 4>(td2BaseKey, td2Expect, state);

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
