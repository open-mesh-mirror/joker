CFLAGS		= -g -O3 -Wall -Wextra
LINKFLAGS	= 
INCLUDES	= 

DESTDIR		= 
PREFIX		= /usr/local
BINDIR		= $(PREFIX)/bin
SBINDIR		= $(PREFIX)/sbin

LIBS		= -lpcap -lpthread

BINARY_NAME	= joker
OBJECTS		= joker.o packets.o node.o tests.o mac_storage.o

all: $(BINARY_NAME)

$(BINARY_NAME): $(OBJECTS)
	$(CC) $(LINKFLAGS) $(DEBUG) $(OBJECTS) $(LIBS) -o $(BINARY_NAME)

%.o: %.c
	$(CC) $(CFLAGS) $(DEBUG) $(INCLUDES) -c $^ -o $@

install: $(BINARY_NAME)
	install -D -m 0755 $^ $(DESTDIR)/$(SBINDIR)/$^

clean:
	rm -f $(OBJECTS)
	rm -f $(BINARY_NAME)

distclean: clean

debug:
	DEBUG="-DDEBUG=1" $(MAKE) all
