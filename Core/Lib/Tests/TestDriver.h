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
**      An Interface of Test Driver.
**
**      @file       Tests/TestDriver.h
**/

#include    <iostream>

#if !defined( CRYPTTOOLS_TESTS_INCLUDED_TEST_DRIVER_H )
#    define   CRYPTTOOLS_TESTS_INCLUDED_TEST_DRIVER_H

//----------------------------------------------------------------
/**   単体テストを起動するエントリポイント。
**
**  @param [in] argc
**  @param [in] argv
**  @return
**/

int
executeCppUnitTests(
        int     argc,
        char *  argv[]);

#if ( HAVE_CPPUNIT )

#    include    <cppunit/extensions/HelperMacros.h>

using   namespace   CPPUNIT_NS;

#else   //  if ! ( HAVE_CPPUNIT )

#include    <iostream>
#include    <stdlib.h>

class   TestFixture
{
public:
    TestFixture();
    virtual  ~TestFixture();

    virtual  void   setUp();
    virtual  void   tearDown();
};

#define     CPPUNIT_TEST_SUITE(classname)       \
public:                                         \
    classname() {                               \
        executeTests();                         \
   }                                            \
protected:                                      \
    void  executeTests()  {

#define     CPPUNIT_TEST(funcname)              \
    funcname()

#define     CPPUNIT_TEST_SUITE_END()            \
    }                                           \
    static  void  run()

#define     CPPUNIT_TEST_SUITE_REGISTRATION(classname)  \
    classname   g_ ## classname ## _Instance;

template  <typename  T>
void  assertEqual(
        const  T  &     vExp,
        const  T  &     vAct,
        const  char  *  szFile,
        const  int      nLine)
{
    if ( vExp != vAct ) {
        std::cerr   <<  "\nEquality Assertion Failed."
                    <<  "\n  Expected : "   <<  vExp
                    <<  "\n  Actual   : "   <<  vAct
                    <<  std::endl;
        exit ( 1 );
    }
    return;
}

#define     CPPUNIT_ASSERT_EQUAL(exp, act)      \
    assertEqual(exp,  act,  __FILE__,  __LINE__)

#endif

//========================================================================
//
//    Helper Functions.
//

//----------------------------------------------------------------
/**   配列の内容を比較する。
**
**  @param [in] vExpect
**  @param [in] vActual
**  @return     一致しなかった要素の数。
**/

template  <typename  T,  size_t  N>
inline  const   int
compareArray(
        const   T   (&vExpect)[N],
        const   T   (&vActual)[N])
{
    int     counter = 0;
    for ( size_t i = 0; i < N; ++ i ) {
        if ( vExpect[i] != vActual[i] ) {
            std::cerr   <<  "\nIndex = "    <<  std::dec
                        <<  i               <<  std::hex
                        <<  ", Expect: 0x"
                        <<  static_cast<uint64_t>(vExpect[i])
                        <<  ", Actual: 0x"
                        <<  static_cast<uint64_t>(vActual[i])
                        <<  std::endl;
            ++ counter;
        }
    }

    return ( counter );
}

#endif
