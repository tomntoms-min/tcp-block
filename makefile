CXX = g++
CXXFLAGS = -Wall -O2
LDFLAGS = -lpcap

TARGET = tcp-block
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
