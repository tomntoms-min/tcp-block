
CXX = g++
CXXFLAGS = -Wall -O2 -std=c++11
LIBS = -lpcap
TARGET = blocker
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
