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
**      An Interface of AdvancedEncryptionStandard class.
**
**      @file       Crypts/AdvancedEncryptionStandard.h
**/

#if !defined( CRYPTTOOLS_CRYPTS_INCLUDED_ADVANCED_ENCRYPTION_STANDARD_H )
#    define   CRYPTTOOLS_CRYPTS_INCLUDED_ADVANCED_ENCRYPTION_STANDARD_H

#include    "CryptTools/Common/CryptToolsTypes.h"

#include    <array>
#include    <vector>

CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

//========================================================================
//
//    AdvancedEncryptionStandard  class.
//

class  AdvancedEncryptionStandard
{

//========================================================================
//
//    Internal Type Definitions.
//
public:

    enum  CryptFlags  {
        CRYPT_FLAGS_AES_128     = 4,
        CRYPT_FLAGS_AES_192     = 6,
        CRYPT_FLAGS_AES_256     = 8,
    };

    enum  {
        NUM_WORDS_IN_ROUND_KEY  = 4
    };

    typedef     std::array<BtWord, NUM_WORDS_IN_ROUND_KEY>  WordKey;

    typedef     std::vector<WordKey>    CryptRoundKeys;

    union  TState
    {
        BtWord      w[4];
        BtByte      s[16];
    };

//========================================================================
//
//    Constructor(s) and Destructor.
//
public:

    //----------------------------------------------------------------
    /**   インスタンスを初期化する
    **  （デフォルトコンストラクタ）。
    **
    **/
    AdvancedEncryptionStandard();

    //----------------------------------------------------------------
    /**   インスタンスを破棄する
    **  （デストラクタ）。
    **
    **/
    virtual  ~AdvancedEncryptionStandard();

//========================================================================
//
//    Public Member Functions (Implement Pure Virtual).
//

//========================================================================
//
//    Public Member Functions (Overrides).
//

//========================================================================
//
//    Public Member Functions (Pure Virtual Functions).
//

//========================================================================
//
//    Public Member Functions (Virtual Functions).
//
public:

    //----------------------------------------------------------------
    /**   暗号文を復号する。
    **
    **  @param [in] cryptKey    暗号化鍵。
    **  @param [in] cryptFlag   フラグ。
    **  @param [in] inData      入力バッファ。
    **  @param[out] outData     出力バッファ。
    **  @return     エラーコードを返す。
    **      -   異常終了の場合は、
    **          エラーの種類を示す非ゼロ値を返す。
    **      -   正常終了の場合は、ゼロを返す。
    **/
    virtual  ErrCode
    decryptData(
            const   LpcByte     baseKey,
            const   CryptFlags  cryptFlag,
            const   LpcByte     inData,
            LpByte  const       outData)  const;

    //----------------------------------------------------------------
    /**   データを暗号化する。
    **
    **  @param [in] cryptKey    暗号化鍵。
    **  @param [in] cryptFlag   フラグ。
    **  @param [in] inData      入力バッファ。
    **  @param[out] outData     出力バッファ。
    **  @return     エラーコードを返す。
    **      -   異常終了の場合は、
    **          エラーの種類を示す非ゼロ値を返す。
    **      -   正常終了の場合は、ゼロを返す。
    **/
    virtual  ErrCode
    encryptData(
            const   LpcByte     baseKey,
            const   CryptFlags  cryptFlag,
            const   LpcByte     inData,
            LpByte  const       outData)  const;

//========================================================================
//
//    Public Member Functions.
//

//========================================================================
//
//    Protected Member Functions.
//

//========================================================================
//
//    For Internal Use Only.
//
private:

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
    static  ErrCode
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
    static  BtByte
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

    //----------------------------------------------------------------
    /**   暗号化手順の AddRoundKey  ステップを実行する
    **
    **  @param [in]     key
    **  @param [in,out] state,
    **  @return     void.
    **/
    static  void
    runTestAddRoundKey(
            const  WordKey  &  key,
            TState          &  state);

    //----------------------------------------------------------------
    /**   復号手順の InvMixColumns  ステップを実行する
    **
    **  @param [in,out] state
    **  @return     void.
    **/
    static  void
    runTestInvMixColumns(
            TState  &  state);

    //----------------------------------------------------------------
    /**   復号手順の InvShiftRows ステップを実行する
    **
    **  @param [in,out] state
    **  @return     void.
    **/
    static  void
    runTestInvShiftRows(
            TState  &  state);

    //----------------------------------------------------------------
    /**   復号手順の InvSubBytes  ステップを実行する
    **
    **  @param [in,out] state
    **  @return     void.
    **/
    static  void
    runTestInvSubBytes(
            TState  &  state);

    //----------------------------------------------------------------
    /**   暗号化手順の MixColumns ステップを実行する
    **
    **  @param [in,out] state
    **  @return     void.
    **/
    static  void
    runTestMixColumns(
            TState  &  state);

    //----------------------------------------------------------------
    /**   暗号化手順の ShiftRows  ステップを実行する
    **
    **  @param [in,out] state
    **  @return     void.
    **/
    static  void
    runTestShiftRows(
            TState  &  state);

    //----------------------------------------------------------------
    /**   暗号化手順の SubBytes ステップを実行する
    **
    **  @param [in,out] state
    **  @return     void.
    **/
    static  void
    runTestSubBytes(
            TState  &  state);

//========================================================================
//
//    Member Variables.
//

//========================================================================
//
//    Other Features.
//
public:
    //  テストクラス。  //
    friend  class   AdvancedEncryptionStandardTest;
};

}   //  End of namespace  Crypts
CRYPTTOOLS_NAMESPACE_END

#endif
