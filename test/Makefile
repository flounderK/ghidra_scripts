
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

TOOL_PREFIX=
CC=$(TOOL_PREFIX)gcc
LD=$(TOOL_PREFIX)ld

ifdef TOOL_PREFIX
$(call allow-override,CC,$(CC))
$(call allow-override,LD,$(LD))
endif

CDEBUG=-g -O0
CFLAGS=-Iinclude -Isrc -shared -fPIC

BINARY=testlib.so

BUILD_DIR=build
DEBUG_DIR=debug
RELEASE_DIR=release
OBJ=$(BUILD_DIR)

OBJECTS += src/main.o

RELEASE_OBJECT_FILES=$(addprefix $(OBJ)/release/, $(OBJECTS))
DBG_OBJECT_FILES=$(addprefix $(OBJ)/debug/, $(OBJECTS))

.PHONY: all clean tests debug release

all: debug release

$(OBJ)/$(DEBUG_DIR)/%.o: CFLAGS += $(CDEBUG)
$(OBJ)/$(DEBUG_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/$(RELEASE_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

# currently unused target
$(OBJ)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

# old unused target
$(BINARY): $(OBJECT_FILES)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ)/$(DEBUG_DIR)/$(BINARY): $(DBG_OBJECT_FILES)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CDEBUG) -o $@ $^

debug: $(OBJ)/$(DEBUG_DIR)/$(BINARY)

$(OBJ)/$(RELEASE_DIR)/$(BINARY): $(RELEASE_OBJECT_FILES)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^

release: $(OBJ)/$(RELEASE_DIR)/$(BINARY)

clean:
	rm -rf $(OBJ) 2>/dev/null
	rm -f $(BINARY) 2>/dev/null
