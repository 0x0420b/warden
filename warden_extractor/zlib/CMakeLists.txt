# Copyright (C) 2008-2013 TrinityCore <http://www.trinitycore.org/>
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

SET(zlib_STAT_SRCS
  adler32.c                                                                                                                                           
  compress.c                                                                                                                                          
  crc32.c                                                                                                                                             
  deflate.c                                                                                                                                           
  example.c                                                                                                                                           
  infback.c                                                                                                                                           
  inffast.c                                                                                                                                           
  inflate.c                                                                                                                                           
  inftrees.c                                                                                                                                          
  trees.c                                                                                                                                             
  uncompr.c                                                                                                                                           
  zutil.c   
)

if(MSVC)
    set(CMAKE_DEBUG_POSTFIX "d")
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
endif()

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
)

set(ZLIB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_library(zlib STATIC ${zlib_STAT_SRCS})

set(ZLIB_PACKAGE_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE PATH "ZLIB source directory")

set_target_properties(zlib PROPERTIES FOLDER "dep/")
