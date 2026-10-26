OPENSSL_DIR := /opt/openssl-1.1

CC := gcc

# Try pkg-config for libteec (preferred). Fallback to common include/lib paths.
TEEC_CFLAGS := $(shell pkg-config --cflags tee 2>/dev/null)
TEEC_LIBS   := $(shell pkg-config --libs tee   2>/dev/null)
ifeq ($(strip $(TEEC_CFLAGS)),)
  TEEC_CFLAGS := -I/usr/include/optee -I/usr/include
endif
ifeq ($(strip $(TEEC_LIBS)),)
  TEEC_LIBS := -lteec
endif

# Common flags
CFLAGS_COMMON  := -Wall -fPIC -g

# Engine object uses local headers (your custom tee_client_api.h, etc.)
CFLAGS_ENGINE  := $(CFLAGS_COMMON) -I$(OPENSSL_DIR)/include -I/usr/include -I.

# Wrapper object must use the **system** OP-TEE header; do NOT include -I.
CFLAGS_WRAPPER := $(CFLAGS_COMMON) -I$(OPENSSL_DIR)/include $(TEEC_CFLAGS) -DTITANSSL_WRAPPER_INTERNAL

LDFLAGS := -Wl,-rpath,$(OPENSSL_DIR)/lib -Wl,-rpath-link,$(OPENSSL_DIR)/lib
LDLIBS  := $(OPENSSL_DIR)/lib/libcrypto.so.1.1 $(TEEC_LIBS)

SRCS   := engine.c tee_client_api.c
OBJS   := engine.o tee_client_api.o
TARGET := titanssl_agnostic.so

all: $(TARGET)

engine.o: engine.c
	$(CC) $(CFLAGS_ENGINE) -c $< -o $@

tee_client_api.o: tee_client_api.c
	$(CC) $(CFLAGS_WRAPPER) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) -shared $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f $(OBJS) $(TARGET)
