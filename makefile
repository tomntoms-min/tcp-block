

CXX = g++
CXXFLAGS = -Wall -O2
LIBS = -lpcap
TARGET = blocker
SRC = blocker.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
