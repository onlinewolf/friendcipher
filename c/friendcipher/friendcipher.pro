TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    fccipher.c \
    fcspeed.c \
    3rd/KeccakP-1600/Optimized64/KeccakP-1600-opt64.c

HEADERS += \
    fccipher.h \
    fcspeed.h \
    3rd/align.h \
    3rd/brg_endian.h \
    3rd/SnP-Relaned.h \
    3rd/KeccakP-1600/Optimized64/ufull/KeccakP-1600-opt64-config.h \
    3rd/KeccakP-1600/Optimized64/KeccakP-1600-SnP.h \

QMAKE_CFLAGS += /arch:AVX2
