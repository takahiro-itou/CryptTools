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
**      An Implementation of AdvancedEncryptionStandard class.
**
**      @file       Crypts/AdvancedEncryptionStandard.cpp
**/

#include    "CryptTools/Crypts/AdvancedEncryptionStandard.h"

CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

namespace  {

/**
**    多項式 m(x) = x^8 + x^4 + x^3 + x + 1
**/
CONSTEXPR_VAR   BtWord  GEN_POLY_MX         = 0x0000001B;

CONSTEXPR_VAR   BtWord  GEN_POLY_MX_MASK    = 0x00000100;

/**
**    S-Box テーブル。
**/

CONSTEXPR_VAR   BtByte  g_tblSBox[256] = {
    //  0x00 ... 0x3F   //
    0x63, 0x7C, 0x77, 0x7B,     0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B,     0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D,     0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF,     0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26,     0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1,     0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3,     0x18, 0x96, 0x05, 0x9A,
};

inline  BtWord
rotWord(const   BtWord  val)
{
    return ( ((val & 0xFF) << 24) | ((val >> 8) & 0x00FFFFFF) );
}

inline  BtWord
subWord(const   BtWord  val)
{
    BtByte  b0  = (val      ) & 0xFF;
    BtByte  b1  = (val >>  8) & 0xFF;
    BtByte  b2  = (val >> 16) & 0xFF;
    BtByte  b3  = (val >> 24) & 0xFF;

    b0  = g_tblSBox[b0];
    b1  = g_tblSBox[b1];
    b2  = g_tblSBox[b2];
    b3  = g_tblSBox[b3];

    return ( (b3 << 24) | (b2 << 16) | (b1 << 8) | b0 );
}

}   //  End of (Unnamed) namespace.


//========================================================================
//
//    AdvancedEncryptionStandard  class.
//

//========================================================================
//
//    Constructor(s) and Destructor.
//

//----------------------------------------------------------------
//    インスタンスを初期化する
//  （デフォルトコンストラクタ）。
//

AdvancedEncryptionStandard::AdvancedEncryptionStandard()
{
}

//----------------------------------------------------------------
//    インスタンスを破棄する
//  （デストラクタ）。
//

AdvancedEncryptionStandard::~AdvancedEncryptionStandard()
{
}

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

//----------------------------------------------------------------
//    各ラウンド用のキーを生成する。
//

ErrCode
AdvancedEncryptionStandard::generateRoundKeys(
        const   LpcByte     baseKey,
        const   int         keySize,
        const   int         numRounds,
        CryptRoundKeys    & outKeys)
{
    //  作業用領域を用意する。  //
    const  int  totalWords  = (numRounds + 1) * NUM_WORDS_IN_ROUND_KEY;
    std::vector<BtWord>     buffer;
    buffer.clear();
    buffer.resize(totalWords);

    const   LpWord  ptrBuf  = &(buffer[0]);

    int         pos     = 0;
    LpcByte     ptrKey  = baseKey;

    for ( ; pos < keySize; ++ pos, ptrKey += 4 ) {
        ptrBuf[pos] = (ptrKey[0])
                | (ptrKey[1] <<  8)
                | (ptrKey[2] << 16)
                | (ptrKey[3] << 24);
    }

    BtWord  conPoly = 0x00000001;
    for ( ; pos < totalWords; ++ pos ) {
        BtWord  tmp = ptrBuf[pos - 1];
        if ( (pos % keySize) == 0 ) {
            tmp = subWord(rotWord(tmp)) ^ conPoly;
            conPoly <<= 1;
            if ( conPoly & GEN_POLY_MX_MASK ) {
                conPoly ^= GEN_POLY_MX;
            }
        } else if ( (keySize > 6) && ((pos % keySize) == 4) ) {
            tmp = subWord(tmp);
        }
        ptrBuf[pos] = ptrBuf[pos - keySize] ^ tmp;
    }

    //  出力用領域を確保する。  //
    outKeys.clear();
    outKeys.resize(numRounds + 1);

    //  作業領域の内容を出力変数にコピーする。  //
    LpcWord ptrRead = ptrBuf;
    for ( int r = 0; r <= numRounds; ++ r ) {
        for ( int idx = 0; idx < NUM_WORDS_IN_ROUND_KEY; ++ idx ) {
            outKeys[r][idx] = *(ptrRead ++);
        }
    }

    return ( ERR_SUCCESS );
}

//----------------------------------------------------------------
//    テーブル SBox の内容を参照する
//  （単体テスト用インターフェイス）。
//

BtByte
AdvancedEncryptionStandard::readSBoxTable(
        const   BtByte  byteVal)
{
    return ( g_tblSBox[byteVal] );
}

}   //  End of namespace  Crypts
CRYPTTOOLS_NAMESPACE_END
