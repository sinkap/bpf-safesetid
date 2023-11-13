# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.27

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /usr/local/google/home/kpsingh/projects/bpf-safesetid/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build

# Include any dependencies generated for this target.
include CMakeFiles/safesetid.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/safesetid.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/safesetid.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/safesetid.dir/flags.make

safesetid.skel.h: safesetid.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: safesetid"
	bash -c "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool/bootstrap/bpftool gen skeleton /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/safesetid.bpf.o > /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/safesetid.skel.h"

safesetid.bpf.o: /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/safesetid.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: safesetid"
	/usr/local/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -idirafter /usr/local/lib/clang/18/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -I/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/../vmlinux/x86 -isystem /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/libbpf -c /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/safesetid.bpf.c -o /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/safesetid.bpf.o

CMakeFiles/safesetid.dir/safesetid.c.o: CMakeFiles/safesetid.dir/flags.make
CMakeFiles/safesetid.dir/safesetid.c.o: /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/safesetid.c
CMakeFiles/safesetid.dir/safesetid.c.o: CMakeFiles/safesetid.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/safesetid.dir/safesetid.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/safesetid.dir/safesetid.c.o -MF CMakeFiles/safesetid.dir/safesetid.c.o.d -o CMakeFiles/safesetid.dir/safesetid.c.o -c /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/safesetid.c

CMakeFiles/safesetid.dir/safesetid.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/safesetid.dir/safesetid.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/safesetid.c > CMakeFiles/safesetid.dir/safesetid.c.i

CMakeFiles/safesetid.dir/safesetid.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/safesetid.dir/safesetid.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/safesetid.c -o CMakeFiles/safesetid.dir/safesetid.c.s

# Object files for target safesetid
safesetid_OBJECTS = \
"CMakeFiles/safesetid.dir/safesetid.c.o"

# External object files for target safesetid
safesetid_EXTERNAL_OBJECTS =

safesetid: CMakeFiles/safesetid.dir/safesetid.c.o
safesetid: CMakeFiles/safesetid.dir/build.make
safesetid: libbpf/libbpf.a
safesetid: CMakeFiles/safesetid.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable safesetid"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/safesetid.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/safesetid.dir/build: safesetid
.PHONY : CMakeFiles/safesetid.dir/build

CMakeFiles/safesetid.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/safesetid.dir/cmake_clean.cmake
.PHONY : CMakeFiles/safesetid.dir/clean

CMakeFiles/safesetid.dir/depend: safesetid.bpf.o
CMakeFiles/safesetid.dir/depend: safesetid.skel.h
	cd /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /usr/local/google/home/kpsingh/projects/bpf-safesetid/src /usr/local/google/home/kpsingh/projects/bpf-safesetid/src /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build /usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/CMakeFiles/safesetid.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/safesetid.dir/depend

