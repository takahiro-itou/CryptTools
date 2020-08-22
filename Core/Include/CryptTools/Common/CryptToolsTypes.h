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
**      Type Definitions.
**
**      @file       Common/CryptToolsTypes.h
**/

#if !defined( CRYPTTOOLS_COMMON_INCLUDED_CRYPT_TOOLS_TYPES_H )
#    define   CRYPTTOOLS_COMMON_INCLUDED_CRYPT_TOOLS_TYPES_H

#include    "CryptToolsSettings.h"

#include    <stddef.h>

CRYPTTOOLS_NAMESPACE_BEGIN

//========================================================================
//
//    Type Definitions.
//

//----------------------------------------------------------------
/**
**    エラーコード。
**/

enum  ErrCode
{

    /**   正常終了。    **/
    ERR_SUCCESS             = 0,

    /**   異常終了。エラーの理由は不明または報告なし。  **/
    ERR_FAILURE             = 1,

    /**   ファイルオープンエラー。  **/
    ERR_FILE_OPEN_ERROR     = 2,

    /**   ファイル入出力エラー。    **/
    ERR_FILE_IO_ERROR       = 3,

    /**   無効なインデックス指定。  **/
    ERR_INDEX_OUT_OF_RANGE  = 4
};

//----------------------------------------------------------------
/**
**    型安全なブール型。
**/

enum  Boolean
{
    BOOL_FALSE  =  0,       /**<  偽。  **/
    BOOL_TRUE   =  1        /**<  真。  **/
};

//----------------------------------------------------------------
/**
**    ファイルの長さを表す型。
**/

typedef     size_t              FileLength;

//----------------------------------------------------------------
/**
**    読み取り専用バッファ。
**/

typedef     const  void  *      LpcReadBuf;

//----------------------------------------------------------------
/**
**    読み書き両用バッファ。
**/

typedef     void  *             LpWriteBuf;

//----------------------------------------------------------------

/**
**    バイト型。
**/
typedef     unsigned  char      BtByte;

/**
**    バイト型の読み取り専用バッファ。
**/
typedef     const  BtByte  *    LpcByte;

/**
**    バイト型の読み書き両用バッファ。
**/

typedef     BtByte  *           LpByte;

//----------------------------------------------------------------
/**
**    ワード型。
**/

typedef     uint32_t            BtWord;

/**
**    ワード型の読み取り専用バッファ。
**/
typedef     const  BtWord  *    LpcWord;

/**
**    ワード型の読み書き両用バッファ。
**/

typedef     BtWord  *           LpWord;

//========================================================================
//
//    安全なポインタ型のキャスト。
//

template  <typename  T>
T  pointer_cast(void  *  p)
{
    return ( static_cast<T>(p) );
}

template  <typename  T>
T  pointer_cast(const  void  *  p)
{
    return ( static_cast<T>(p) );
}

CRYPTTOOLS_NAMESPACE_END

#endif
