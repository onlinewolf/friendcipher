TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    fccrypt.cpp \
    fcexception.cpp \
    fckeccak.cpp \
    fcmixer.cpp \
    main.cpp \
    3rd/keccak.c

DISTFILES += \
    .gitignore

HEADERS += \
    fccrypt.h \
    fcexception.h \
    fckeccak.h \
    fcmixer.h \
    3rd/keccak.h
