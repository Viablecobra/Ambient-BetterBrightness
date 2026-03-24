cmake_minimum_required(VERSION 3.31)
project(BetterBrightness LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


include(gamepwnage.cmake)

include_directories(gamepwnage/includes)

add_library(${CMAKE_PROJECT_NAME} SHARED
        main.cpp
        stub.h
)


target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
        -g0
)

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
)

add_library(nise INTERFACE IMPORTED)


set_property(TARGET nise PROPERTY
        INTERFACE_INCLUDE_DIRECTORIES
        ${CMAKE_CURRENT_LIST_DIR}
)

set_property(TARGET nise PROPERTY
        INTERFACE_LINK_LIBRARIES
        gamepwnage
        "-L${CMAKE_CURRENT_LIST_DIR}/libs/${ANDROID_ABI} -lnise"
)
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
        "-Wl,-z,max-page-size=16384"
        "-Wl,-z,common-page-size=16384"
)


target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${GAMEPWNAGE_DIR}/src
)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
        gamepwnage
        android
        log
        nise
)