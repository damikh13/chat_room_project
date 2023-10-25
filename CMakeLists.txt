cmake_minimum_required(VERSION 3.12)
project(ChatRoom)

set(CMAKE_CXX_STANDARD 17)  # Use C++17 or later

# Add the executable for the server
add_executable(server
    src/server.cpp
    src/ChatRoom.cpp
    src/User.cpp
    src/Message.cpp
    src/Logger.cpp
    src/ConfigParser.cpp
)

# Add the executable for the client
add_executable(client
    src/client.cpp
    src/ChatRoom.cpp
    src/User.cpp
    src/Message.cpp
    src/Logger.cpp
    src/ConfigParser.cpp
)

# Linking external libraries (not for now)

# Configure include directories (headers)
target_include_directories(server PRIVATE include)
target_include_directories(client PRIVATE include)

# Add other configuration or compiler flags as needed
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Install the executables (optional)
# install(TARGETS server client DESTINATION bin)

