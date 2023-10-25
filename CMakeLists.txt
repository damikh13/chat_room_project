cmake_minimum_required(VERSION 3.12)
project(ChatRoom)

set(CMAKE_CXX_STANDARD 17)  # Use C++17 or later

# Add the executable for chat room program
add_executable(ChatRoom
    src/main.cpp
    src/ChatRoom.cpp
    src/User.cpp
    src/Message.cpp
    src/Logger.cpp
    src/ConfigParser.cpp
)

# Linking external libraries (not for now)

# Configure include directories (headers)
target_include_directories(ChatRoom PRIVATE include)

# Add other configuration or compiler flags as needed
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Install the executable (optional)
# install(TARGETS ChatRoom DESTINATION bin)
