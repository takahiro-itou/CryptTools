
##
##    バイナリのビルドとインストール。
##

##
##    List of Directories.
##

MODULE_DIR_NAME         =  Binary
SUBDIRS                 =  .

include  $(top_srcdir)/.M4/Makefile.DirList.inc

##
##    List of Source and Header Files.
##

##
##    Internal Libraries.
##

##
##    Compile and Link Options.
##

AM_CPPFLAGS          =  \
        -I${INCTOP_SOURCE_DIR}
AM_CFLAGS               =
AM_CXXFLAGS             =
AM_LDFLAGS              =  -L${LIBTOP_BINARY_DIR}

##
##    List of Installs.
##

bin_PROGRAMS            =  \
        CryptTools

dist_noinst_DATA        =  \
        CMakeLists.txt

##
##    Build Executables.
##

CryptTools_SOURCES      =  CryptTools.cpp
CryptTools_LDADD        =

