cmake_minimum_required(VERSION 3.16)
project(aegis_desktop VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# ---- options ---------------------------------------------------------------
option(AEGIS_WITH_WEBVIEW "Open in a native desktop window via webview" ON)
option(AEGIS_WITH_CURL    "Enable live RSS security feeds (needs libcurl)" OFF)

# ---- embed the web UI into a C++ header (regenerated if Python is present) --
set(GEN_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/src/assets_generated.h)
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/web)
  file(GLOB_RECURSE WEB_ASSETS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/web/*)
  add_custom_command(
    OUTPUT ${GEN_HEADER}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_assets.py
            ${CMAKE_CURRENT_SOURCE_DIR}/web ${GEN_HEADER}
    DEPENDS ${WEB_ASSETS} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_assets.py
    COMMENT "Embedding AEGIS web assets into src/assets_generated.h"
    VERBATIM)
  add_custom_target(aegis_assets DEPENDS ${GEN_HEADER})
endif()

# ---- executable ------------------------------------------------------------
add_executable(aegis-desktop src/main.cpp)
target_include_directories(aegis-desktop PRIVATE third_party src)
if(TARGET aegis_assets)
  add_dependencies(aegis-desktop aegis_assets)
endif()

find_package(Threads REQUIRED)
target_link_libraries(aegis-desktop PRIVATE Threads::Threads)

# ---- optional: live feeds via libcurl --------------------------------------
if(AEGIS_WITH_CURL)
  find_package(CURL REQUIRED)
  target_link_libraries(aegis-desktop PRIVATE CURL::libcurl)
  target_compile_definitions(aegis-desktop PRIVATE AEGIS_WITH_CURL)
endif()

# ---- optional: native window via webview (fetched at configure time) -------
if(AEGIS_WITH_WEBVIEW)
  include(FetchContent)
  FetchContent_Declare(
    webview
    GIT_REPOSITORY https://github.com/webview/webview
    GIT_TAG 0.12.0)
  FetchContent_MakeAvailable(webview)
  target_link_libraries(aegis-desktop PRIVATE webview::core)
  target_compile_definitions(aegis-desktop PRIVATE AEGIS_WITH_WEBVIEW)
endif()

# ---- install + packaging ---------------------------------------------------
install(TARGETS aegis-desktop RUNTIME DESTINATION bin BUNDLE DESTINATION .)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/README.md
        DESTINATION share/aegis OPTIONAL)

set(CPACK_PACKAGE_NAME "AEGIS")
set(CPACK_PACKAGE_VENDOR "Global Response Team")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "AEGIS — Field Security Operations Suite (Desktop)")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "AEGIS")

if(WIN32)
  set(CPACK_GENERATOR "NSIS;ZIP")
  set(CPACK_NSIS_PACKAGE_NAME "AEGIS")
  set(CPACK_NSIS_DISPLAY_NAME "AEGIS Field Security Operations")
  set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
elseif(APPLE)
  set(CPACK_GENERATOR "DragNDrop;TGZ")
else()
  set(CPACK_GENERATOR "DEB;TGZ")
  set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Global Response Team")
  set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
  # Runtime libs for the webview window on Linux (WebKitGTK / GTK3):
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "libwebkit2gtk-4.1-0, libgtk-3-0")
endif()
include(CPack)
