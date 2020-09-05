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

#include    <memory.h>

CRYPTTOOLS_NAMESPACE_BEGIN
namespace  Crypts  {

namespace  {

/**
**    多項式 m(x) = x^8 + x^4 + x^3 + x + 1
**/
CONSTEXPR_VAR   BtWord  GEN_POLY_MX         = 0x0000011B;

CONSTEXPR_VAR   BtWord  GEN_POLY_MX_MASK    = 0x00000100;

#include    "AesTables.h"

//----------------------------------------------------------------

#define     ADD_ROUND_KEY(key, state)                           \
{                                                               \
    state.w[0]  ^= key[0];                                      \
    state.w[1]  ^= key[1];                                      \
    state.w[2]  ^= key[2];                                      \
    state.w[3]  ^= key[3];                                      \
}

#define     INV_MIX_COLUMN(state)                               \
{                                                               \
    for ( int c = 0; c < 4; ++ c ) {                            \
        const   BtByte  s0      = state.s[c * 4    ];           \
        const   BtByte  s1      = state.s[c * 4 + 1];           \
        const   BtByte  s2      = state.s[c * 4 + 2];           \
        const   BtByte  s3      = state.s[c * 4 + 3];           \
        const   BtByte  s0_xE   = g_tblMixCol[s0][2];           \
        const   BtByte  s0_x9   = g_tblMixCol[s0][3];           \
        const   BtByte  s0_xD   = g_tblMixCol[s0][4];           \
        const   BtByte  s0_xB   = g_tblMixCol[s0][5];           \
        const   BtByte  s1_xE   = g_tblMixCol[s1][2];           \
        const   BtByte  s1_x9   = g_tblMixCol[s1][3];           \
        const   BtByte  s1_xD   = g_tblMixCol[s1][4];           \
        const   BtByte  s1_xB   = g_tblMixCol[s1][5];           \
        const   BtByte  s2_xE   = g_tblMixCol[s2][2];           \
        const   BtByte  s2_x9   = g_tblMixCol[s2][3];           \
        const   BtByte  s2_xD   = g_tblMixCol[s2][4];           \
        const   BtByte  s2_xB   = g_tblMixCol[s2][5];           \
        const   BtByte  s3_xE   = g_tblMixCol[s3][2];           \
        const   BtByte  s3_x9   = g_tblMixCol[s3][3];           \
        const   BtByte  s3_xD   = g_tblMixCol[s3][4];           \
        const   BtByte  s3_xB   = g_tblMixCol[s3][5];           \
        state.s[c*4  ]  = (s0_xE ^ s1_xB ^ s2_xD ^ s3_x9);      \
        state.s[c*4+1]  = (s0_x9 ^ s1_xE ^ s2_xB ^ s3_xD);      \
        state.s[c*4+2]  = (s0_xD ^ s1_x9 ^ s2_xE ^ s3_xB);      \
        state.s[c*4+3]  = (s0_xB ^ s1_xD ^ s2_x9 ^ s3_xE);      \
    }                                                           \
}

#define     INV_SUB_BYTES(state)                                \
{                                                               \
    state.s[ 0] = g_tblInvSBox[ state.s[ 0] ];                  \
    state.s[ 1] = g_tblInvSBox[ state.s[ 1] ];                  \
    state.s[ 2] = g_tblInvSBox[ state.s[ 2] ];                  \
    state.s[ 3] = g_tblInvSBox[ state.s[ 3] ];                  \
    state.s[ 4] = g_tblInvSBox[ state.s[ 4] ];                  \
    state.s[ 5] = g_tblInvSBox[ state.s[ 5] ];                  \
    state.s[ 6] = g_tblInvSBox[ state.s[ 6] ];                  \
    state.s[ 7] = g_tblInvSBox[ state.s[ 7] ];                  \
    state.s[ 8] = g_tblInvSBox[ state.s[ 8] ];                  \
    state.s[ 9] = g_tblInvSBox[ state.s[ 9] ];                  \
    state.s[10] = g_tblInvSBox[ state.s[10] ];                  \
    state.s[11] = g_tblInvSBox[ state.s[11] ];                  \
    state.s[12] = g_tblInvSBox[ state.s[12] ];                  \
    state.s[13] = g_tblInvSBox[ state.s[13] ];                  \
    state.s[14] = g_tblInvSBox[ state.s[14] ];                  \
    state.s[15] = g_tblInvSBox[ state.s[15] ];                  \
}

#define     INV_SHIFT_ROWS(state)                               \
{                                                               \
    const   BtWord  w0  = state.w[0];                           \
    const   BtWord  w1  = state.w[1];                           \
    const   BtWord  w2  = state.w[2];                           \
    const   BtWord  w3  = state.w[3];                           \
    state.w[0]  = (w0 & 0x000000FF) | (w3 & 0x0000FF00)         \
            | (w2 & 0x00FF0000) | (w1 & 0xFF000000);            \
    state.w[1]  = (w1 & 0x000000FF) | (w0 & 0x0000FF00)         \
            | (w3 & 0x00FF0000) | (w2 & 0xFF000000);            \
    state.w[2]  = (w2 & 0x000000FF) | (w1 & 0x0000FF00)         \
            | (w0 & 0x00FF0000) | (w3 & 0xFF000000);            \
    state.w[3]  = (w3 & 0x000000FF) | (w2 & 0x0000FF00)         \
            | (w1 & 0x00FF0000) | (w0 & 0xFF000000);            \
}

#define     MIX_COLUMN(state)                                   \
{                                                               \
    for ( int c = 0; c < 4; ++ c ) {                            \
        const   BtByte  s0      = state.s[c * 4    ];           \
        const   BtByte  s1      = state.s[c * 4 + 1];           \
        const   BtByte  s2      = state.s[c * 4 + 2];           \
        const   BtByte  s3      = state.s[c * 4 + 3];           \
        const   BtByte  s0_x2   = g_tblMixCol[s0][0];           \
        const   BtByte  s1_x2   = g_tblMixCol[s1][0];           \
        const   BtByte  s2_x2   = g_tblMixCol[s2][0];           \
        const   BtByte  s3_x2   = g_tblMixCol[s3][0];           \
        const   BtByte  s0_x3   = g_tblMixCol[s0][1];           \
        const   BtByte  s1_x3   = g_tblMixCol[s1][2];           \
        const   BtByte  s2_x3   = g_tblMixCol[s2][3];           \
        const   BtByte  s3_x3   = g_tblMixCol[s3][4];           \
        state.s[c*4  ]  = (s0_x2 ^ s1_x3 ^ s2 ^ s3);            \
        state.s[c*4+1]  = (s0 ^ s1_x2 ^ s2_x3 ^ s3);            \
        state.s[c*4+2]  = (s0 ^ s1 ^ s2_x2 ^ s3_x3);            \
        state.s[c*4+3]  = (s0_x3 ^ s1 ^ s2 ^ s3_x2);            \
    }                                                           \
}

#define     SUB_BYTES(state)                                    \
{                                                               \
    state.s[ 0] = g_tblSBox[ state.s[ 0] ];                     \
    state.s[ 1] = g_tblSBox[ state.s[ 1] ];                     \
    state.s[ 2] = g_tblSBox[ state.s[ 2] ];                     \
    state.s[ 3] = g_tblSBox[ state.s[ 3] ];                     \
    state.s[ 4] = g_tblSBox[ state.s[ 4] ];                     \
    state.s[ 5] = g_tblSBox[ state.s[ 5] ];                     \
    state.s[ 6] = g_tblSBox[ state.s[ 6] ];                     \
    state.s[ 7] = g_tblSBox[ state.s[ 7] ];                     \
    state.s[ 8] = g_tblSBox[ state.s[ 8] ];                     \
    state.s[ 9] = g_tblSBox[ state.s[ 9] ];                     \
    state.s[10] = g_tblSBox[ state.s[10] ];                     \
    state.s[11] = g_tblSBox[ state.s[11] ];                     \
    state.s[12] = g_tblSBox[ state.s[12] ];                     \
    state.s[13] = g_tblSBox[ state.s[13] ];                     \
    state.s[14] = g_tblSBox[ state.s[14] ];                     \
    state.s[15] = g_tblSBox[ state.s[15] ];                     \
}

#define     SHIFT_ROWS(state)                                   \
{                                                               \
    const   BtWord  w0  = state.w[0];                           \
    const   BtWord  w1  = state.w[1];                           \
    const   BtWord  w2  = state.w[2];                           \
    const   BtWord  w3  = state.w[3];                           \
    state.w[0]  = (w0 & 0x000000FF) | (w1 & 0x0000FF00)         \
            | (w2 & 0x00FF0000) | (w3 & 0xFF000000);            \
    state.w[1]  = (w1 & 0x000000FF) | (w2 & 0x0000FF00)         \
            | (w3 & 0x00FF0000) | (w0 & 0xFF000000);            \
    state.w[2]  = (w2 & 0x000000FF) | (w3 & 0x0000FF00)         \
            | (w0 & 0x00FF0000) | (w1 & 0xFF000000);            \
    state.w[3]  = (w3 & 0x000000FF) | (w0 & 0x0000FF00)         \
            | (w1 & 0x00FF0000) | (w2 & 0xFF000000);            \
}

//----------------------------------------------------------------

inline  BtWord
rotWord(const   BtWord  val)
{
    return ( ((val & 0xFF) << 24) | ((val >> 8) & 0x00FFFFFF) );
}

//----------------------------------------------------------------

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

//----------------------------------------------------------------
//    暗号文を復号する。
//

ErrCode
AdvancedEncryptionStandard::decryptData(
        const   LpcByte     baseKey,
        const   CryptFlags  cryptFlag,
        const   LpcByte     inData,
        LpByte  const       outData)  const
{
    const  int  keyLen      = static_cast<int>(cryptFlag);
    const  int  numRounds   = keyLen + 6;
    CryptRoundKeys  rKeys;
    TState          state;

    memcpy(state.s, inData, sizeof(state.s));

    generateRoundKeys(baseKey, keyLen, numRounds, rKeys);
    ADD_ROUND_KEY(rKeys[numRounds], state);

    for ( int curRound = numRounds - 1; curRound >= 1; -- curRound ) {
        INV_SHIFT_ROWS(state);
        INV_SUB_BYTES(state);
        ADD_ROUND_KEY(rKeys[curRound], state);
        INV_MIX_COLUMN(state);
    }

    INV_SHIFT_ROWS(state);
    INV_SUB_BYTES(state);
    ADD_ROUND_KEY(rKeys[0], state);

    memcpy(outData, state.s, sizeof(state.s));

    return ( ERR_SUCCESS );
}

//----------------------------------------------------------------
//    データを暗号化する。
//

ErrCode
AdvancedEncryptionStandard::encryptData(
        const   LpcByte     baseKey,
        const   CryptFlags  cryptFlag,
        const   LpcByte     inData,
        LpByte  const       outData)  const
{
    const  int  keyLen      = static_cast<int>(cryptFlag);
    const  int  numRounds   = keyLen + 6;
    CryptRoundKeys  rKeys;
    TState          state;

    memcpy(state.s, inData, sizeof(state.s));

    generateRoundKeys(baseKey, keyLen, numRounds, rKeys);

    ADD_ROUND_KEY(rKeys[0], state);

    for ( int curRound = 1; curRound < numRounds; ++ curRound ) {
        SUB_BYTES(state);
        SHIFT_ROWS(state);
        MIX_COLUMN(state);
        ADD_ROUND_KEY(rKeys[curRound], state);
    }

    SUB_BYTES(state);
    SHIFT_ROWS(state);
    ADD_ROUND_KEY(rKeys[numRounds], state);

    memcpy(outData, state.s, sizeof(state.s));

    return ( ERR_SUCCESS );
}

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
//    テーブル Inv SBox の内容を参照する
//

BtByte
AdvancedEncryptionStandard::readInvSBoxTable(
        const   BtByte  byteVal)
{
    return ( g_tblInvSBox[byteVal] );
}

//----------------------------------------------------------------
//    テーブル MixColConv の内容を参照する。
//

BtByte
AdvancedEncryptionStandard::readMixColConvTable(
        const   BtByte  idxByte,
        const   BtByte  mulVal)
{
    return ( g_tblMixCol[idxByte][mulVal] );
}

//----------------------------------------------------------------
//    テーブル SBox の内容を参照する
//

BtByte
AdvancedEncryptionStandard::readSBoxTable(
        const   BtByte  byteVal)
{
    return ( g_tblSBox[byteVal] );
}

//----------------------------------------------------------------
//    暗号化手順の AddRoundKey  ステップを実行する
//

void
AdvancedEncryptionStandard::runTestAddRoundKey(
        const  WordKey  &  key,
        TState          &  state)
{
    ADD_ROUND_KEY(key, state);
}

//----------------------------------------------------------------
//    復号手順の InvMixColumns  ステップを実行する
//

void
AdvancedEncryptionStandard::runTestInvMixColumns(
        TState  &  state)
{
    INV_MIX_COLUMN(state);
}

//----------------------------------------------------------------
//    復号手順の InvShiftRows ステップを実行する
//

void
AdvancedEncryptionStandard::runTestInvShiftRows(
        TState  &  state)
{
    INV_SHIFT_ROWS(state);
}

//----------------------------------------------------------------
//    復号手順の InvSubBytes  ステップを実行する
//

void
AdvancedEncryptionStandard::runTestInvSubBytes(
        TState  &  state)
{
    INV_SUB_BYTES(state);
}

//----------------------------------------------------------------
//    暗号化手順の MixColumns ステップを実行する
//

void
AdvancedEncryptionStandard::runTestMixColumns(
        TState  &  state)
{
    MIX_COLUMN(state);
}

//----------------------------------------------------------------
//    暗号化手順の ShiftRows  ステップを実行する
//

void
AdvancedEncryptionStandard::runTestShiftRows(
        TState  &  state)
{
    SHIFT_ROWS(state);
}

//----------------------------------------------------------------
//    暗号化手順の SubBytes ステップを実行する
//

void
AdvancedEncryptionStandard::runTestSubBytes(
        TState  &  state)
{
    SUB_BYTES(state);
}

}   //  End of namespace  Crypts
CRYPTTOOLS_NAMESPACE_END
