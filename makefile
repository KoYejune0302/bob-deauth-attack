CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11

all: deauth-attack

deauth-attack: main.o
	$(CXX) $(CXXFLAGS) -o deauth-attack main.o

main.o: main.cpp deauth.h auth.h
	$(CXX) $(CXXFLAGS) -c main.cpp

clean:
	rm -f *.o deauth-attack
