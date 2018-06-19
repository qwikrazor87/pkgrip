CC = gcc
CFLAGS = -Wall -Wextra -Werror -I./libkirk

CFLAGS+=-O2

TARGET1 = libkirk/libkirk.a
OBJS1 = libkirk/kirk_engine.o libkirk/aes.o libkirk/sha1.o libkirk/amctrl.o libkirk/bn.o libkirk/ec.o

TARGET2 = pkgrip
OBJS2 = pkgrip.o

all: $(TARGET1)

$(TARGET1): $(OBJS1)
	$(AR) rcs $@ $(OBJS1)

all: $(TARGET2)

$(TARGET2): $(OBJS2)
	$(CC) $(CFLAGS) -o $@ $(OBJS2) -L ./libkirk -lkirk -lz

clean:
	rm -rf *.o libkirk/*.o
