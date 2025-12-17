CC ?= gcc
AR ?= ar
CHK_SOURCES ?= $(SRCS)
CPPFLAGS ?= -MMD -MP
CFLAGS ?= -flto -ffat-lto-objects -march=native --std=c89 -g -Ideps/ -Isrc/ -Wall -Wextra -Wpedantic -Wconversion -Wformat-security -Wshadow -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wnull-dereference -Wfloat-equal -Wundef -Wpointer-arith -Wbad-function-cast -Wlogical-op -Wmissing-braces -Wcast-align -Wstrict-overflow=5 -ftrapv
LDFLAGS ?= -flto -g -static

BUILD = build_$(CC)

SRCS := src/elf.c
OBJECTS := $(SRCS:src/%.c=$(BUILD)/%.o)
HEADERS := $(wildcard src/*.h)
EXE := elf
LIB := libcolonq-elf.a

prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
includedir ?= $(prefix)/include
libdir ?= $(exec_prefix)/lib

.PHONY: all clean install check-syntax

all: $(EXE) $(LIB)

$(EXE): $(BUILD)/main.o $(LIB)
	$(CC) -o $@ $^ $(LDFLAGS)

$(LIB): $(OBJECTS)
	ar rcs $@ $^

$(BUILD):
	mkdir $(BUILD)/

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

clean:
	-rm $(EXE)
	-rm $(LIB)
	-rm -r $(BUILD)/

TAGS: $(SRCS)
	ctags --output-format=etags $^

install: $(EXE) $(LIB)
	mkdir -p $(DESTDIR)$(bindir) $(DESTDIR)$(libdir) $(DESTDIR)$(includedir)
	install $(EXE) $(DESTDIR)$(bindir)/$(EXE)
	install $(LIB) $(DESTDIR)$(libdir)/$(LIB)
	install $(HEADERS) $(DESTDIR)$(includedir)

check-syntax: TAGS
	gcc $(CFLAGS) -fsyntax-only $(CHK_SOURCES)

-include $(BUILD)/main.d
-include $(OBJECTS:.o=.d)
