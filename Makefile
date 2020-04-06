CC=clang
TARGET=ipxnet
SRCFILES=ipxserver.c
LIBS=-lwebsockets

all: $(TARGET)

$(TARGET): $(SRCFILES) *.h
	$(CC) -ggdb3 -Wall --std=c99 $(CXXFLAGS) $(SRCFILES) $(LIBS) -o $(TARGET)

clean:
	rm -f $(TARGET) ipxnet.log
