
Set (COMMONLIBS
        ${PROJECT_NAME}-${LIBRARIES_TARGET_PREFIX}Crypts
)

Add_Executable        (CryptTools  CryptTools.cpp)
Target_Link_Libraries (CryptTools   ${COMMONLIBS})

