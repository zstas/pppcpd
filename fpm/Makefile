TARGET ?= fibmgr
SRCDIR = ./src
OBJDIR = ./obj

SRC = $(wildcard $(SRCDIR)/*.cpp $(SRCDIR)/fpm/*.cc $(SRCDIR)/qpb/*cc)
OBJ = $(addprefix $(OBJDIR)/,$(notdir $(SRC:.cpp=.o)))

CPPFLAGS ?= -g -Wall -std=c++17 -Isrc/
LDLIBS += -lpthread -lvapiclient -lboost_system -lmnl -lprotobuf

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
