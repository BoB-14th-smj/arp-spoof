TARGET=arp-spoof
CXXFLAGS=-g -Wall

all: $(TARGET)

$(TARGET) : main.cpp ethernet.cpp
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpcap

clean:
	rm -f $(TARGET)
	rm -f *.o
