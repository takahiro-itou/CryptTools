﻿//  -*-  coding: utf-8-with-signature;  mode: c++  -*-  //
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
CONSTEXPR_VAR   BtWord  GEN_POLY_MX         = 0x0000011B;

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
    0x07, 0x12, 0x80, 0xE2,     0xEB, 0x27, 0xB2, 0x75,

    //  0x40 ... 0x7F   //
    0x09, 0x83, 0x2C, 0x1A,     0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3,     0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED,     0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39,     0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB,     0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F,     0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F,     0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21,     0x10, 0xFF, 0xF3, 0xD2,

    //  0x80 ... 0xBF   //
    0xCD, 0x0C, 0x13, 0xEC,     0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D,     0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC,     0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14,     0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A,     0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62,     0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D,     0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA,     0x65, 0x7A, 0xAE, 0x08,

    //  0xC0 ... 0xFF   //
    0xBA, 0x78, 0x25, 0x2E,     0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F,     0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66,     0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9,     0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11,     0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9,     0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D,     0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F,     0xB0, 0x54, 0xBB, 0x16
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
