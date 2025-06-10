
CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11
LIBS = -lpcap
TARGET = tcp-block
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
