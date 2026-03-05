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
**      An Implementation of Test Case 'AesSteps05'.
**
**      @file       Crypts/Tests/AesSteps05Test.cpp
**/

#include    "AdvancedEncryptionStandardTest.h"


CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AesSteps05Test  class.
//
/**
**    クラス AdvancedEncryptionStandard の単体テスト。
**/

class  AesSteps05Test : public  AdvancedEncryptionStandardTest
{
    CPPUNIT_TEST_SUITE(AesSteps05Test);
    CPPUNIT_TEST(testGenerateRoundKeys5);
    CPPUNIT_TEST(testRunDecryptSteps5);
    CPPUNIT_TEST(testRunEncryptSteps5);
    CPPUNIT_TEST_SUITE_END();

public:

    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:

    void  testGenerateRoundKeys5();
    void  testRunDecryptSteps5();
    void  testRunEncryptSteps5();

};

CPPUNIT_TEST_SUITE_REGISTRATION( AesSteps05Test );

//========================================================================
//
//    Test Data.
//

//----------------------------------------------------------------
//    Test Data # 5

const   BtByte  td5BaseKey[24]  = {
    0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17
};

const   BtWord  td5Expect[13][5][4] = {
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
        { 0x13121110, 0x17161514, 0xF9F24658, 0xFEF4435C },
        { 0x0676634F, 0x85AAE043, 0xD0C9F8AF, 0xE40DFA41 }
    }, {
        { 0x6F38FB84, 0x97ACE11A, 0x70DD4179, 0x69D72D83 },
        { 0x69DDE184, 0x6FD7411A, 0x97382D79, 0x70ACFB83 },
        { 0x797F489F, 0x665F954F, 0xAB86FC2A, 0x29ABF1D7 },
        { 0xF5FE4A54, 0xFAF04758, 0xE9E25648, 0xFEF4435C },
        { 0x8C8102CB, 0x9CAFD217, 0x4264AA62, 0xD75FB28B }
    }, {
        { 0x640C771F, 0xDE79B5F0, 0x2C43ACAA, 0x0ECF373D },
        { 0x0E43B51F, 0x64CFACF0, 0xDE0C37AA, 0x2C79773D },
        { 0xCB3EA5B7, 0xA0759DBF, 0x79FC0EC4, 0x11CC74B6 },
        { 0xB349F940, 0x4DBDBA1C, 0xB843F048, 0x42B3B710 },
        { 0x78775CF7, 0xEDC827A3, 0xC1BFFE8C, 0x537FC3A6 }
    }, {
        { 0xBCF54A68, 0x55E8CC0A, 0x7808BB64, 0xEDD22E24 },
        { 0xED08CC68, 0xBCD2BB0A, 0x55F52E64, 0x78E84A24 },
        { 0xBD981E7A, 0x14D1B6AC, 0xDD44691A, 0x3E2DEB06 },
        { 0xAB51E158, 0x55A5A204, 0x41B5FF7E, 0x0C084562 },
        { 0x16C9FF22, 0x417414A8, 0x9CF19664, 0x3225AE64 }
    }, {
        { 0x47DD1693, 0x8392FAC2, 0xDEA19043, 0x233FE443 },
        { 0x23A1FA93, 0x473F90C2, 0x83DDE443, 0xDE921643 },
        { 0xB355A7AA, 0x7CE5FF4C, 0xE1986FEF, 0xE6131CF0 },
        { 0xB44BB52A, 0xF6F8023A, 0x5DA9E362, 0x080C4166 },
        { 0x071E1280, 0x8A1DFD76, 0xBC318C8D, 0xEE1F5D96 }
    }, {
        { 0xC572C9CD, 0x7EA45438, 0x65C7645D, 0x28C04C90 },
        { 0x28C754CD, 0xC5C06438, 0x7E724C5D, 0x65A4C990 },
        { 0x8F741F92, 0x7D936ED9, 0x25772D62, 0x0CA58BBA },
        { 0x728501F5, 0x7E8D4497, 0xCAC6F1BD, 0x3C3EF387 },
        { 0xFDF11E67, 0x031E2A4E, 0xEFB1DCDF, 0x309B783D }
    }, {
        { 0x54A17285, 0x7B72E52F, 0xDFC8869E, 0x0414BC27 },
        { 0x04C8E585, 0x5414862F, 0x7BA1BC9E, 0xDF727227 },
        { 0xB1E713E9, 0x4B7D508F, 0x52F67E22, 0xCCCB8A75 },
        { 0x619710E5, 0x699B5183, 0x9E7C1534, 0xE0F151A3 },
        { 0xD070030C, 0x22E6010C, 0xCC8A6B16, 0x2C3ADBD6 }
    }, {
        { 0x70517BFE, 0x938E7CFE, 0x4B7E7F47, 0x7180B9F6 },
        { 0x717E7CFE, 0x70807FFE, 0x9351B947, 0x4B8E7BF6 },
        { 0xF9EDF56C, 0x060AEB96, 0x1CF24E9C, 0x6257C2BF },
        { 0x2A37A01E, 0x16095399, 0x779E437C, 0x1E0512FF },
        { 0xD3DA5572, 0x1003B80F, 0x6B6C0DE0, 0x7C52D040 }
    }, {
        { 0x6657FC40, 0xCA7B6C76, 0x7F50D7E1, 0x10007009 },
        { 0x10506C40, 0x6600D776, 0xCA5770E1, 0x7F7BFC09 },
        { 0xDCBC7874, 0x810BA5E8, 0x907A32D4, 0x62821809 },
        { 0x880E7EDD, 0x68FF2F7E, 0x42C88F60, 0x54C1DCF9 },
        { 0x54B206A9, 0xE9F48A96, 0xD2B2BDB4, 0x3643C4F0 }
    }, {
        { 0x20376FD3, 0x1EBF7E90, 0xB5377A8D, 0x051A1C8C },
        { 0x05377ED3, 0x201A7A90, 0x1E371C8D, 0xB5BF6F8C },
        { 0x2DCC730D, 0x8BBE6A8F, 0x9BDDF20C, 0x2E423DB8 },
        { 0x235F9F85, 0x3D5A8D7A, 0x5229C0C0, 0x3AD6EFBE },
        { 0x0E93EC88, 0xB6E4E7F5, 0xC9F432CC, 0x1494D206 }
    }, {
        { 0xABDCCEC4, 0x4E6994E6, 0xDDBF234B, 0xFA22B56F },
        { 0xFABF94C4, 0xAB2223E6, 0x4EDCB54B, 0xDD69CE6F },
        { 0x9320D771, 0x7D676D3B, 0x288F0BC0, 0xB70F8E23 },
        { 0x781E60DE, 0x2CDFBC27, 0x0F8023A2, 0x32DAAED8 },
        { 0xEB3EB7AF, 0x51B8D11C, 0x270F2862, 0x85D520FB }
    }, {
        { 0xE9B2A979, 0xD16C3E9C, 0xCC7634AA, 0x9703B70F },
        { 0x97763E79, 0xE903349C, 0xD1B2B7AA, 0xCC6CA90F },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x330A97A4, 0x09DC781A, 0x71C218C4, 0x5D1DA4E3 },
        { 0xA47CA9DD, 0xE0DF4C86, 0xA070AF6E, 0x91710DEC }
    }
};

//========================================================================
//
//    Tests.
//

void  AesSteps05Test::testGenerateRoundKeys5()
{
    typedef     Testee::CryptRoundKeys  CryptRoundKeys;

    Testee          aes;
    CryptRoundKeys  w;

    const   BtByte  keys[24] = {
        0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,     0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,     0x14, 0x15, 0x16, 0x17
    };

    const   Testee::WordKey     expect[] = {
        { 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C },
        { 0x13121110, 0x17161514, 0xF9F24658, 0xFEF4435C },
        { 0xF5FE4A54, 0xFAF04758, 0xE9E25648, 0xFEF4435C },
        { 0xB349F940, 0x4DBDBA1C, 0xB843F048, 0x42B3B710 },
        { 0xAB51E158, 0x55A5A204, 0x41B5FF7E, 0x0C084562 },
        { 0xB44BB52A, 0xF6F8023A, 0x5DA9E362, 0x080C4166 },
        { 0x728501F5, 0x7E8D4497, 0xCAC6F1BD, 0x3C3EF387 },
        { 0x619710E5, 0x699B5183, 0x9E7C1534, 0xE0F151A3 },
        { 0x2A37A01E, 0x16095399, 0x779E437C, 0x1E0512FF },
        { 0x880E7EDD, 0x68FF2F7E, 0x42C88F60, 0x54C1DCF9 },
        { 0x235F9F85, 0x3D5A8D7A, 0x5229C0C0, 0x3AD6EFBE },
        { 0x781E60DE, 0x2CDFBC27, 0x0F8023A2, 0x32DAAED8 },
        { 0x330A97A4, 0x09DC781A, 0x71C218C4, 0x5D1DA4E3 }
    };

    CPPUNIT_ASSERT_EQUAL(
            ERR_SUCCESS,
            generateRoundKeys(keys, 6, 12, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));

    return;
}

void  AesSteps05Test::testRunDecryptSteps5()
{
    Testee          aes;

    Testee::TState  state   = {
        0xA47CA9DD, 0xE0DF4C86, 0xA070AF6E, 0x91710DEC
    };

    runDecryptSteps<12, 6>(td5BaseKey, td5Expect, state);

    return;
}

void  AesSteps05Test::testRunEncryptSteps5()
{
    Testee          aes;

    Testee::TState  state   = {
        0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC
    };

    runEncryptSteps<12, 6>(td5BaseKey, td5Expect, state);

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
