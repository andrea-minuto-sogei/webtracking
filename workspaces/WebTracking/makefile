# ============================================================
#  mod_web_tracking — Apache shared module
#  Requires: gcc-toolset-15, IHS headers/libs, zlib-ng (bundled)
# ============================================================

CC      := /opt/rh/gcc-toolset-15/root/bin/gcc
SRCDIR  := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Output
TARGET  := $(HOME)/webtracking/lib/mod_web_tracking.so

# Source files
CSRCS   := $(wildcard $(SRCDIR)*.c)
CXXSRCS := $(wildcard $(SRCDIR)*.cpp)

# Static libraries linked in
LIBSTDCXX := /opt/rh/gcc-toolset-15/root/usr/lib/gcc/x86_64-redhat-linux/15/libstdc++.a
LIBZNG    := $(SRCDIR)zlib-ng/lib/libz-ng.a

# Compiler flags (shared for both C and C++ translation units)
COMMON_FLAGS := \
    -D_LARGEFILE64_SOURCE=1 \
    -I$(HOME)/IHS/include \
    -I$(SRCDIR)zlib-ng/include \
    -O3 \
    -Wall \
    -fmessage-length=0 \
    -fPIC

# Language-specific standards
CFLAGS   := $(COMMON_FLAGS) -std=c17
CXXFLAGS := $(COMMON_FLAGS) -std=c++23

# Linker flags
LDFLAGS  := \
    -L$(HOME)/IHS/lib \
    -shared \
    -static-libstdc++ \
    -Wl,--exclude-libs,libstdc++.a:libz-ng.a

# Derived object lists (placed in SRCDIR to keep the tree clean)
COBJS   := $(CSRCS:.c=.o)
CXXOBJS := $(CXXSRCS:.cpp=.o)
OBJS    := $(COBJS) $(CXXOBJS)

# ============================================================

# Archive paths
BINZIP  := $(HOME)/archives/webtracking-bin.zip
SRCZIP  := $(HOME)/archives/webtracking-src.zip
VERFILE := $(HOME)/webtracking/bin/version.txt

# .PHONY declares targets that are NOT real files — just named recipes.
# Without it, if a file with the same name as a target existed on disk,
# make would see it as "up to date" and silently skip the recipe.
# Any target that does not produce a file matching its own name belongs here.
.PHONY: all clean archives

all: $(TARGET)

# $@  — the target of the current rule (the file being produced)
# $^  — all prerequisites, space-separated and deduplicated
#        (used in the link step: every .o and .a passed to the linker)
# $<  — the first prerequisite only
#        (used in compile steps: the single .c/.cpp source file;
#         avoids accidentally passing header files to the compiler)

$(TARGET): $(OBJS) $(LIBSTDCXX) $(LIBZNG)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $^   # $^ = all .o + .a files

# Compile C sources
$(SRCDIR)%.o: $(SRCDIR)%.c
	$(CC) $(CFLAGS) -c -o $@ $<   # $< = the matched .c file

# Compile C++ sources
$(SRCDIR)%.o: $(SRCDIR)%.cpp
	$(CC) $(CXXFLAGS) -c -o $@ $<   # $< = the matched .cpp file

clean:
	rm -f $(OBJS) $(TARGET)

# archives — build version.txt then package binary and source zips
#   The two zip commands run from $HOME so that paths inside the archive
#   are relative (e.g. webtracking/lib/... and workspaces/WebTracking/...)
archives: $(TARGET)
	@mkdir -p $(HOME)/archives
	grep -E -o 'Web Tracking Apache Module .*?\)' \
	    $(HOME)/workspaces/WebTracking/mod_web_tracking.c \
	    > $(VERFILE)
	echo 'Universal Splunk Forwarder Check' \
	    $$(grep -oP 'VERSION=\K.+' $(HOME)/webtracking/bin/check.sh) \
	    '(BASH)' \
	    >> $(VERFILE)
	cd $(HOME) && zip -r -FS -dc $(BINZIP) \
	    webtracking/bin \
	    webtracking/lib \
	    webtracking/logs_archive \
	    webtracking/update \
	    webtracking/logs
	cd $(HOME) && zip -r -FS -dc $(SRCZIP) \
	    workspaces/WebTracking/ \
	    workspaces/Collector/ \
	    info
