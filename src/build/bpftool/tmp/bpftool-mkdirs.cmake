# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/../bpftool/src"
  "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool/src/bpftool-build"
  "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool"
  "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool/tmp"
  "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool/src/bpftool-stamp"
  "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool/src"
  "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool/src/bpftool-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool/src/bpftool-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/usr/local/google/home/kpsingh/projects/bpf-safesetid/src/build/bpftool/src/bpftool-stamp${cfgdir}") # cfgdir has leading slash
endif()
