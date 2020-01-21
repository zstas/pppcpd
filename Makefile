TARGET ?= pppcpd
SRCDIR = ./src
OBJDIR = ./obj

SRC = $(wildcard $(SRCDIR)/*.cpp main.cpp)
OBJ = $(addprefix $(OBJDIR)/,$(notdir $(SRC:.cpp=.o)))

CPPFLAGS ?= -g -Wall -std=c++17
LDLIBS += -lpthread -lvapiclient

$(TARGET): $(OBJ)
	$(CXX) $(LDFLAGS) $(OBJ) -o $@ $(LOADLIBES) $(LDLIBS)

$(OBJDIR):
	mkdir -p $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp $(OBJDIR)
	$(CXX) -c $(CPPFLAGS) $< -o $@

.PHONY: clean start
clean:
	$(RM) $(TARGET) $(OBJ)

start:
	sudo ./$(TARGET)
