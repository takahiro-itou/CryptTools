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
**      An Interface of Test Case 'AdvancedEncryptionStandard'.
**
**      @file       Crypts/Tests/AdvancedEncryptionStandardTest.h
**/

#if !defined( CRYPTTOOLS_CRYPTS_TESTS_INCLUDED_AES_TEST_H )
#    define   CRYPTTOOLS_CRYPTS_TESTS_INCLUDED_AES_TEST_H

#include    "TestDriver.h"
#include    "CryptTools/Crypts/AdvancedEncryptionStandard.h"

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
    CPPUNIT_TEST(testGenerateRoundKeys5);
    CPPUNIT_TEST(testReadInvSBoxTable);
    CPPUNIT_TEST(testReadMixColConvTable);
    CPPUNIT_TEST(testReadSBoxTable);
    CPPUNIT_TEST(testRunDecryptSteps1);
    CPPUNIT_TEST(testRunDecryptSteps2);
    CPPUNIT_TEST(testRunDecryptSteps3);
    CPPUNIT_TEST(testRunDecryptSteps4);
    CPPUNIT_TEST(testRunDecryptSteps5);
    CPPUNIT_TEST(testRunEncryptSteps1);
    CPPUNIT_TEST(testRunEncryptSteps2);
    CPPUNIT_TEST(testRunEncryptSteps3);
    CPPUNIT_TEST(testRunEncryptSteps4);
    CPPUNIT_TEST(testRunEncryptSteps5);
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

    static  void
    generatePolyInvTable(
            BtWord  (& tableInvs) [256]);

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
    void  testGenerateRoundKeys5();
    void  testReadInvSBoxTable();
    void  testReadMixColConvTable();
    void  testReadSBoxTable();
    void  testRunDecryptSteps1();
    void  testRunDecryptSteps2();
    void  testRunDecryptSteps3();
    void  testRunDecryptSteps4();
    void  testRunDecryptSteps5();
    void  testRunEncryptSteps1();
    void  testRunEncryptSteps2();
    void  testRunEncryptSteps3();
    void  testRunEncryptSteps4();
    void  testRunEncryptSteps5();
};

}   //  End of namespace  Crypts
CRYPTTOOLS_NAMESPACE_END

#endif
