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

protected:
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
    static  inline  void
    runDecryptSteps(
            const   BtByte  (&baseKey)[KEYLEN * 4],
            const   BtWord  (&expect)[ROUNDS+1][5][STLEN],
            Testee::TState  & state);

    template  <int ROUNDS, int KEYLEN, size_t STLEN=4>
    static  inline  void
    runEncryptSteps(
            const   BtByte  (&baseKey)[KEYLEN * 4],
            const   BtWord  (&expect)[ROUNDS+1][5][STLEN],
            Testee::TState  & state);

protected:

    //----------------------------------------------------------------
    /**   各ラウンド用のキーを生成する。
    **
    **  @param [in] baseKey     暗号化鍵。
    **  @param [in] keySize     キーサイズ（ワード単位）。
    **  @param [in] numRounds   ラウンド数。
    **  @param[out] outKeys     生成されたラウンド用キー。
    **  @return     エラーコードを返す。
    **      -   異常終了の場合は、
    **          エラーの種類を示す非ゼロ値を返す。
    **      -   正常終了の場合は、ゼロを返す。
    **/
    static  inline  ErrCode
    generateRoundKeys(
            const   LpcByte     baseKey,
            const   int         keySize,
            const   int         numRounds,
            CryptRoundKeys    & outKeys);

    //----------------------------------------------------------------
    /**   テーブル Inv SBox の内容を参照する
    **
    **  @param [in] byteVal
    **  @return
    **/
    static  inline  BtByte
    readInvSBoxTable(
            const   BtByte  byteVal);

    //----------------------------------------------------------------
    /**   テーブル MixColConv の内容を参照する。
    **
    **  @param [in] idxByte,
    **  @param [in] mulVal
    **  @return
    **/
    static  BtByte
    readMixColConvTable(
            const   BtByte  idxByte,
            const   BtByte  mulVal);

    //----------------------------------------------------------------
    /**   テーブル SBox の内容を参照する
    **
    **  @param [in] byteVal
    **  @return
    **/
    static  BtByte
    readSBoxTable(
            const   BtByte  byteVal);

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

    for ( size_t j = 0; j < STLEN; ++ j ) {
        CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
    }

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    for ( i = ROUNDS - 1; i >= 1; -- i ) {
        Testee::runTestInvShiftRows(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i + 1][0], state.w));

        Testee::runTestInvSubBytes(state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));

        for ( size_t j = 0; j < STLEN; ++ j ) {
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

    for ( size_t j = 0; j < STLEN; ++ j ) {
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

    for ( size_t j = 0; j < STLEN; ++ j ) {
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

        for ( size_t j = 0; j < STLEN; ++ j ) {
            CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
        }

        Testee::runTestAddRoundKey(rKeys[i], state);
        CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));
    }

    Testee::runTestSubBytes(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][0], state.w));

    Testee::runTestShiftRows(state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][1], state.w));

    for ( size_t j = 0; j < STLEN; ++ j ) {
        CPPUNIT_ASSERT_EQUAL(expect[i][3][j], rKeys[i][j]);
    }

    Testee::runTestAddRoundKey(rKeys[i], state);
    CPPUNIT_ASSERT_EQUAL(0, compareArray(expect[i][4], state.w));

    return;
}

//----------------------------------------------------------------
//    各ラウンド用のキーを生成する。
//

inline  ErrCode
AdvancedEncryptionStandardTest::generateRoundKeys(
        const   LpcByte     baseKey,
        const   int         keySize,
        const   int         numRounds,
        CryptRoundKeys    & outKeys)
{
    return ( Testee::generateRoundKeys(
                     baseKey, keySize, numRounds, outKeys)
    );
}

//----------------------------------------------------------------
//    テーブル Inv SBox の内容を参照する
//

inline  BtByte
AdvancedEncryptionStandardTest::readInvSBoxTable(
        const   BtByte  byteVal)
{
    return ( Testee::readInvSBoxTable(byteVal) );
}

//----------------------------------------------------------------
//    テーブル MixColConv の内容を参照する。
//

inline  BtByte
AdvancedEncryptionStandardTest::readMixColConvTable(
        const   BtByte  idxByte,
        const   BtByte  mulVal)
{
    return ( Testee::readMixColConvTable(idxByte, mulVal) );
}

//----------------------------------------------------------------
//    テーブル SBox の内容を参照する
//

inline  BtByte
AdvancedEncryptionStandardTest::readSBoxTable(
        const   BtByte  byteVal)
{
    return ( Testee::readSBoxTable(byteVal) );
}

}   //  End of namespace  Crypts
CRYPTTOOLS_NAMESPACE_END

#endif
