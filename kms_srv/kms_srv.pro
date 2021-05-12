TEMPLATE = app
CONFIG += c++11 console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        kms_define.c \
        kms_proc.c \
        kms_srv.c \
        kms_util.c

HEADERS += \
    kms_define.h \
    kms_proc.h \
    kms_srv.h \
    kms_util.h


INCLUDEPATH += "../../PKILib"

mac {
    INCLUDEPATH += "../../PKILib/lib/mac/debug/cmpossl/include"
    INCLUDEPATH += "/usr/local/include"
    LIBS += -L"/usr/local/lib" -lltdl

    LIBS += -L"../../build-PKILib-Desktop_Qt_5_11_3_clang_64bit-Debug" -lPKILib
    LIBS += -L"../../PKILib/lib/mac/debug/cmpossl/lib" -lcrypto -lssl
    LIBS += -L"/usr/local/lib" -lltdl
    LIBS += -lsqlite3
}

win32 {
    contains(QT_ARCH, i386 ) {
        message( "kms_srv 32bit" )
        INCLUDEPATH += "C:\msys64\mingw32\include"

        Debug {
            INCLUDEPATH += "../../PKILib/lib/win32/debug/cmpossl/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Debug/debug" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win32/debug/cmpossl/lib" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win32/cmpossl/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_32_bit-Release/release" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win32/cmpossl/lib" -lcrypto -lssl
        }

        LIBS += -L"C:\msys64\mingw32\lib" -lltdl -lsqlite3
    } else {
        message( "kms_srv 64bit" )
        INCLUDEPATH += "C:\msys64\mingw64\include"

        Debug {
            INCLUDEPATH += "../../PKILib/lib/win64/debug/cmpossl/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Debug/debug" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win64/debug/cmpossl/lib" -lcrypto -lssl
        } else {
            INCLUDEPATH += "../../PKILib/lib/win64/cmpossl/include"
            LIBS += -L"../../build-PKILib-Desktop_Qt_5_13_2_MinGW_64_bit-Release/release" -lPKILib -lws2_32
            LIBS += -L"../../PKILib/lib/win64/cmpossl/lib" -lcrypto -lssl
        }

        LIBS += -L"C:\msys64\mingw64\lib" -lltdl -lsqlite3
    }

}

DISTFILES += \
    ../kms_srv.cfg
