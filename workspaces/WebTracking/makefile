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

# Object files go into a dedicated build subdirectory
BUILDDIR := $(SRCDIR)build
COBJS    := $(patsubst $(SRCDIR)%.c,  $(BUILDDIR)/%.o, $(CSRCS))
CXXOBJS  := $(patsubst $(SRCDIR)%.cpp,$(BUILDDIR)/%.o, $(CXXSRCS))
OBJS     := $(COBJS) $(CXXOBJS)

# ============================================================

# Archive paths
BINZIP   := $(HOME)/archives/webtracking-bin.zip
SRCZIP   := $(HOME)/archives/webtracking-src.zip
VERFILE  := $(HOME)/webtracking/bin/version.txt
CHECKSH  := $(HOME)/webtracking/bin/check.sh
MODC     := $(SRCDIR)mod_web_tracking.c

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
	@echo "Build $(TARGET)"
	@$(CC) $(LDFLAGS) -o $@ $^

# Compile C sources  (output goes to build/)
$(BUILDDIR)/%.o: $(SRCDIR)%.c
	@mkdir -p $(BUILDDIR)
	@echo "Compile $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

# Compile C++ sources  (output goes to build/)
$(BUILDDIR)/%.o: $(SRCDIR)%.cpp
	@mkdir -p $(BUILDDIR)
	@echo "Compile $<"
	@$(CC) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rvf $(BUILDDIR) $(TARGET)

# $(VERFILE) is rebuilt only when mod_web_tracking.c or check.sh is newer.
$(VERFILE): $(MODC) $(CHECKSH)
	@mkdir -p $(dir $@)
	@echo "Update $(VERFILE)"
	@grep -E -o 'Web Tracking Apache Module .*?\)' $(MODC) > $@
	@echo 'Universal Splunk Forwarder Check' \
	    $$(grep -oP 'VERSION=\K.+' $(CHECKSH)) \
	    '(BASH)' \
	    >> $@

# archives — ensure version.txt is current, then package binary and source zips.
#   The two zip commands run from $HOME so that paths inside the archive
#   are relative (e.g. webtracking/lib/... and workspaces/WebTracking/...)
archives: $(TARGET) $(VERFILE)
	@mkdir -p $(HOME)/archives
	@echo "Build $(BINZIP)"
	@cd $(HOME) && zip -r -FS -dc $(BINZIP) \
	    webtracking/bin \
	    webtracking/lib \
	    webtracking/logs_archive \
	    webtracking/update \
	    webtracking/logs
	@echo "Build $(SRCZIP)"
	@cd $(HOME) && zip -r -FS -dc $(SRCZIP) \
	    workspaces/WebTracking/ \
	    workspaces/Collector/ \
	    info \
	    -x 'workspaces/WebTracking/build/*'
