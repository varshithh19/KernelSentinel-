CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Iinclude -std=c99
LDFLAGS ?= -lpthread

TARGET = kernelsentinel_collector
SRCS = src/collector.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
