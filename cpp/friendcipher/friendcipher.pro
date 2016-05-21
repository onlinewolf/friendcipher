TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    fccipher.cpp \
    fcexception.cpp \
    fcmixer.cpp \
    main.cpp \
    fcrng.cpp \
    fctspeed.cpp \
    fchash.cpp

DISTFILES += \
    .gitignore

HEADERS += \
    fccipher.h \
    fcexception.h \
    fcmixer.h \
    fcrng.h \
    fctspeed.h \
    fchash.h
	
QMAKE_CXXFLAGS += /arch:AVX2
