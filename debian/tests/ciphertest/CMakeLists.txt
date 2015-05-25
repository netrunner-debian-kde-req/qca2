project(ciphertest)

cmake_minimum_required(VERSION 2.8.12)

option(USE_QT5 "Build for Qt5" OFF)

if(USE_QT5)
  find_package(Qt5Core REQUIRED)
  find_package(Qca-qt5 REQUIRED)
else()
  find_package(Qt4 REQUIRED)
  find_package(Qca REQUIRED)
endif()

add_executable(ciphertest ciphertest.cpp)

if(USE_QT5)
  target_link_libraries(ciphertest Qt5::Core qca-qt5)
else()
  target_link_libraries(ciphertest ${QT_QTCORE_LIBRARY} qca)
endif()
