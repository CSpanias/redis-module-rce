# Minimal Makefile for Redis RCE module
CC = gcc
CFLAGS = -Wall -fPIC -O2 -std=gnu99 -I.
LDFLAGS = -shared
TARGET = module.so
SRC = module.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
