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
**      An Implementation of Test Case 'AesSteps04'.
**
**      @file       Crypts/Tests/AesSteps04Test.cpp
**/

#include    "AdvancedEncryptionStandardTest.h"


CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AesSteps04Test  class.
//
/**
**    クラス AdvancedEncryptionStandard の単体テスト。
**/

class  AesSteps04Test : public  AdvancedEncryptionStandardTest
{
    CPPUNIT_TEST_SUITE(AesSteps04Test);
    CPPUNIT_TEST(testGenerateRoundKeys4);
    CPPUNIT_TEST(testRunDecryptSteps4);
    CPPUNIT_TEST(testRunEncryptSteps4);
    CPPUNIT_TEST_SUITE_END();

public:

    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:

    void  testGenerateRoundKeys4();
    void  testRunDecryptSteps4();
    void  testRunEncryptSteps4();

};

CPPUNIT_TEST_SUITE_REGISTRATION( AesSteps04Test );

//========================================================================
//
//    Test Data.
//

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

void  AesSteps04Test::testGenerateRoundKeys4()
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
            generateRoundKeys(keys, 8, 14, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));

    return;
}

void  AesSteps04Test::testRunDecryptSteps4()
{
    Testee          aes;

    Testee::TState  state   = {
        0xCAB7A28E, 0xBF456751, 0x9049FCEA, 0x8960494B
    };

    runDecryptSteps<14, 8>(td4BaseKey, td4Expect, state);

    return;
}

void  AesSteps04Test::testRunEncryptSteps4()
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
