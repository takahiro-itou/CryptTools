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

#if !defined( CRYPTTOOLS_COMMON_INCLUDED_ADVANCED_ENCRYPTION_STANDARD_H )
#    define   CRYPTTOOLS_COMMON_INCLUDED_ADVANCED_ENCRYPTION_STANDARD_H

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

    enum  {
        NUM_WORDS_IN_ROUND_KEY  = 4
    };

    typedef     std::array<BtWord, NUM_WORDS_IN_ROUND_KEY>  WordKey;

    typedef     std::vector<WordKey>    CryptRoundKeys;

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
