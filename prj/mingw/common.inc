#--------------------------------------------------------------------
# Common definitions
#--------------------------------------------------------------------

CC      = gcc
CXX     = g++
LD      = g++
GETUUID = eu-unstrip -n -e
OBJCOPY = objcopy

CFLAGS   = -fno-strict-aliasing -mfpmath=sse -msse4.2 -pipe -g3 -Wno-unknown-pragmas -Wno-long-long -Wno-reorder -Wno-missing-braces -Wno-unused-function -Wno-invalid-offsetof -std=c++0x
CXXFLAGS = -fno-strict-aliasing -mfpmath=sse -msse4.2 -pipe -g3 -Wno-unknown-pragmas -Wno-long-long -Wno-reorder -Wno-missing-braces -Wno-unused-function -Wno-invalid-offsetof -std=c++0x
LDFLAGS  = -fno-strict-aliasing

CFLAGS_DEBUG   = -O0 -D_DEBUG
CXXFLAGS_DEBUG = -O0 -D_DEBUG
LDFLAGS_DEBUG  = 

CFLAGS_RELEASE   = -fno-exceptions -O2 -w
CXXFLAGS_RELEASE = -fno-exceptions -O2 -w
LDFLAGS_RELEASE  = -fno-exceptions

# Number of processors
PCNT := $(shell expr `cat /proc/cpuinfo | grep processor | wc -l`)
#PCNT := 4

# Top dir
ROOT_PATH = ../../
3RD_PATH = $(ROOT_PATH)/3rd_lib

# OpenSSL
OPENSSL = openssl
OPENSSL_CLEAN = openssl_clean
OPENSSL_ROOT_PATH = $(ROOT_PATH)/extern/openssl
OPENSSL_INCLUDE_PATH = $(OPENSSL_ROOT_PATH)/include
OPENSSL_PROJECT_PATH = $(OPENSSL_ROOT_PATH)/prj/linux/openssl
CRYPTO_PROJECT_PATH = $(OPENSSL_ROOT_PATH)/prj/linux/crypto

