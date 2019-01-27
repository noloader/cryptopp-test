LOCAL_PATH := $(call my-dir)

SRC_LSH := \
	../src/hmac.c \
	../src/lsh.c \
	../src/check_neon.c \
	../src/no_arch/lsh256.c \
	../src/no_arch/lsh512.c \
	../src/neon/lsh256_neon.c.neon \
	../src/neon/lsh512_neon.c.neon \
	
SRC_ANDROID_LIB := \
	LshNative.cpp \
	LshWrapper.cpp \
	HmacLshNative.cpp \
	HmacLshWrapper.cpp \

###############################################################################
# LSH static library - PIE enabled 
###############################################################################
include $(CLEAR_VARS)

LOCAL_MODULE := lsh_static
LOCAL_MODULE_FILENAME := liblsh_static
LOCAL_ARM_NEON := true
LOCAL_CFLAGS += -O2
LOCAL_SRC_FILES := $(SRC_LSH)
LOCAL_STATIC_LIBRARIES := cpufeatures

include $(BUILD_STATIC_LIBRARY)

###############################################################################
# Android library - PIE enabled 
###############################################################################
include $(CLEAR_VARS)

LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie

LOCAL_MODULE := liblsh_android
LOCAL_ARM_NEON := true
LOCAL_CFLAGS += -O2
LOCAL_LDFLAGS += -shared                              # to build shared library
LOCAL_SRC_FILES := $(SRC_ANDROID_LIB)
#LOCAL_SHARED_LIBRARIES := lsh_shared
LOCAL_STATIC_LIBRARIES := lsh_static
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)

$(call import-module,android/cpufeatures)
