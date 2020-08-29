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
**      An Implementation of Test Case 'AesSteps01'.
**
**      @file       Crypts/Tests/AesSteps01Test.cpp
**/

#include    "AdvancedEncryptionStandardTest.h"


CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AesSteps01Test  class.
//
/**
**    クラス AdvancedEncryptionStandard の単体テスト。
**/

class  AesSteps01Test : public  AdvancedEncryptionStandardTest
{
    CPPUNIT_TEST_SUITE(AesSteps01Test);
    CPPUNIT_TEST(testGenerateRoundKeys1);
    CPPUNIT_TEST(testRunDecryptSteps1);
    CPPUNIT_TEST(testRunEncryptSteps1);
    CPPUNIT_TEST_SUITE_END();

public:

    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:

    void  testGenerateRoundKeys1();
    void  testRunDecryptSteps1();
    void  testRunEncryptSteps1();

};

CPPUNIT_TEST_SUITE_REGISTRATION( AesSteps01Test );

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
    {
        { 0xA8F64332, 0x8D305A88, 0xA2983131, 0x340737E0 },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0x16157E2B, 0xA6D2AE28, 0x8815F7AB, 0x3C4FCF09 },
        { 0xBEE33D19, 0x2BE2F4A0, 0x2A8DC69A, 0x0848F8E9 }
    }, {
        { 0xAE1127D4, 0xF198BFE0, 0xE55DB4B8, 0x3052411E },
        { 0x305DBFD4, 0xAE52B4E0, 0xF11141B8, 0xE598271E },
        { 0xE5816604, 0x9A19CBE0, 0x7AD3F848, 0x4C260628 },
        { 0x17FEFAA0, 0xB12C5488, 0x3939A323, 0x05766C2A },
        { 0xF27F9CA4, 0x2B359F68, 0x43EA5B6B, 0x49506A02 }
    }, {
        { 0x89D2DE49, 0xF196DB45, 0x1A87397F, 0x3B530277 },
        { 0x3B87DB49, 0x89533945, 0xF1D2027F, 0x1A96DE77 },
        { 0xF1CA4D58, 0xAC5A4B1B, 0xA8CAE7DB, 0xE5B06B1B },
        { 0xF295C2F2, 0x43B9967A, 0x7A803559, 0x7FF65973 },
        { 0x035F8FAA, 0xEFE3DD61, 0xD24AD282, 0x9A463268 }
    }, {
        { 0x7BCF73AC, 0xDF11C1EF, 0xB5D6B513, 0xB85A2345 },
        { 0xB8D6C1AC, 0x7B5AB5EF, 0xDFCF2313, 0xB5117345 },
        { 0x9309EC75, 0x33630B20, 0x7CCFC053, 0xDCD025BB },
        { 0x7D47803D, 0x3EFE1647, 0x447E231E, 0x3B887A6D },
        { 0xEE4E6C48, 0x0D9D1D67, 0x38B1E34D, 0xE7585FD6 }
    }, {
        { 0x282F5052, 0xD75EA485, 0x07C811E3, 0x946ACFF6 },
        { 0x94C8A452, 0x286A1185, 0xD72FCFE3, 0x075E50F6 },
        { 0xA9DAD60F, 0xBF383160, 0x6B10C06F, 0x0113B35E },
        { 0x41A544EF, 0x7F5B52A8, 0x3B2571B6, 0x00AD0BDB },
        { 0xE87F92E0, 0xC06363C8, 0x5035B1D9, 0x01BEB885 }
    }, {
        { 0x9BD24FE1, 0xBAFBFBE8, 0x5396C835, 0x7CAE6C97 },
        { 0x7C96FBE1, 0x9BAEC8E8, 0xBAD26C35, 0x53FB4F97 },
        { 0xADA9D125, 0x68D111BD, 0x8E333AB6, 0xB0C04C4C },
        { 0xF8C6D1D4, 0x879D837C, 0xBCB8F2CA, 0xBC15F911 },
        { 0x556F00F1, 0xEF4C92C1, 0x328BC87C, 0x0CD5B55D }
    }, {
        { 0xFCA863A1, 0xDF294F78, 0x233DE810, 0xFE03D54C },
        { 0xFE3D4FA1, 0xFC03E878, 0xDFA8D510, 0x2329634C },
        { 0x6D8D864B, 0x80894A2C, 0xE8F49D33, 0xD818D237 },
        { 0x7AA3886D, 0xFD3E0B11, 0x4186F9DB, 0xFD9300CA },
        { 0x172E0E26, 0x7DB7413D, 0xA97264E8, 0x258BD2FD }
    }, {
        { 0xF031ABF7, 0xFFA98327, 0xD340439B, 0x3F3DB554 },
        { 0x3F4083F7, 0xF03D4327, 0xFF31B59B, 0xD3A9AB54 },
        { 0xBFB51514, 0xEC151646, 0xD7564627, 0x43D82A34 },
        { 0x0EF7544E, 0xF3C95F5F, 0xB24FA684, 0x4FDCA64E },
        { 0xB142415A, 0x1FDC4919, 0x6519E0A3, 0x0C048C7A }
    }, {
        { 0xC82C83BE, 0xC0863BD4, 0x4DD4E10A, 0xFEF264DA },
        { 0xFED43BBE, 0xC8F2E1D4, 0xC02C640A, 0x4D8683DA },
        { 0xD12F5100, 0xFF89C8B1, 0xCD6D7654, 0xEA991BFA },
        { 0x2173D2EA, 0xD2BA8DB5, 0x60F52B31, 0x2F298D7F },
        { 0xF05C83EA, 0x2D334504, 0xAD985D65, 0xC5B09685 }
    }, {
        { 0x8C4AEC87, 0xD8C36EF2, 0x95464C4D, 0xA6E79097 },
        { 0xA6466E87, 0x8CE74CF2, 0xD84A904D, 0x95C3EC97 },
        { 0xED943747, 0xA5E4D440, 0xA63A70A3, 0xBC429F4C },
        { 0xF36677AC, 0x21DCFA19, 0x4129D128, 0x6E005C57 },
        { 0x1EF240EB, 0x84382E59, 0xE713A18B, 0xD242C31B }
    }, {
        { 0x728909E9, 0x5F0731CB, 0x947D323D, 0xB52C2EAF },
        { 0xB57D31E9, 0x722C32CB, 0x5F892E3D, 0x940709AF },
        { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF },
        { 0xA8F914D0, 0x8925EEC9, 0xC80C3FE1, 0xA60C63B6 },
        { 0x1D842539, 0xFB09DC02, 0x978511DC, 0x320B6A19 }
    }
};

//========================================================================
//
//    Tests.
//

void  AesSteps01Test::testGenerateRoundKeys1()
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
            generateRoundKeys(keys, 4, 10, w));
    CPPUNIT_ASSERT_EQUAL(0, checkRoundKeys(expect, w));

    return;
}

void  AesSteps01Test::testRunDecryptSteps1()
{
    Testee          aes;

    Testee::TState  state   = {
        0x1D842539, 0xFB09DC02, 0x978511DC, 0x320B6A19
    };

    runDecryptSteps<10, 4>(td1BaseKey, td1Expect, state);

    return;
}

void  AesSteps01Test::testRunEncryptSteps1()
{
    Testee          aes;

    Testee::TState  state   = {
        0xA8F64332, 0x8D305A88, 0xA2983131, 0x340737E0
    };

    runEncryptSteps<10, 4>(td1BaseKey, td1Expect, state);

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
