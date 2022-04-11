CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lssl -lcrypto -lcurl

SDIR = ./src
_SOURCE = main.c p2p.c bencode.c dict.c
SOURCE = $(addprefix $(SDIR)/, $(_SOURCE))

IDIR = ./include
_DEPS = p2p.h bencode.h list.h
DEPS = $(addprefix $(IDIR)/, $(_DEPS))

.PHONY: all clean

all: c_bittorrent

c_bittorrent: $(SOURCE) $(DEPS)
	$(CC) $(CFLAGS) -I$(IDIR) $(SOURCE) -o $@ $(LIBS)

clean:
	rm -f c_bittorrent
