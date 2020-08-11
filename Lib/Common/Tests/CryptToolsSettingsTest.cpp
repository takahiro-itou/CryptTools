//  -*-  coding: utf-8; mode: c++  -*-  //
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
**      An Implementation of Test Case 'CryptToolsSettings'.
**
**      @file       Common/Tests/CryptToolsSettingsTest.cpp
**/

#include    "TestDriver.h"
#include    "CryptTools/Common/CryptToolsSettings.h"

CRYPTTOOLS_NAMESPACE_BEGIN

//========================================================================
//
//    CryptToolsSettingsTest  class.
//
/**
**    クラス CryptToolsSettings の単体テスト。
**/

class  CryptToolsSettingsTest : public  TestFixture
{
    CPPUNIT_TEST_SUITE(CryptToolsSettingsTest);
    CPPUNIT_TEST(testNameSpace);
    CPPUNIT_TEST_SUITE_END();

public:
    virtual  void   setUp()     override    { }
    virtual  void   tearDown()  override    { }

private:
    void  testNameSpace();
};

CPPUNIT_TEST_SUITE_REGISTRATION( CryptToolsSettingsTest );

//========================================================================
//
//    Tests.
//

void  CryptToolsSettingsTest::testNameSpace()
{
    return;
}

CRYPTTOOLS_NAMESPACE_END

//========================================================================
//
//    エントリポイント。
//

int  main(int argc, char * argv[])
{
    return ( executeCppUnitTests(argc, argv) );
}
