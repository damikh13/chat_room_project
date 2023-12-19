# Chat Room Project

This is an academic chat project implemented in C++. It allows users to exchange messages within a network using a simple console interface.

## Building

To build the project, follow these steps:

1. Create a build directory and navigate into it:
   `mkdir build`
   `cd build`

2. Configure the project using CMake:
   `cmake ..`

3. Build the project:
   `cmake --build .`

Your executable will be located in the project root directory.

## Running

To run the project, you will need to start both the server (first) and client sides (second).

### Server Side

Run the server with the following command:
`./server cfg/server/server.cfg`

### Client Side

(Example based on the first client)
Run the client with the following command:
`./client cfg/clients/first.cfg`

## Usage

1. **Registration and Authorization:**

    - When you first connect to the chat room, you have the option to either register or authorize.
    - If you choose to register, a new password will be added to the server's database (database.txt was changed to normal form).
    - If you choose to authorize as a registered user, you will have three (by default, configurable in the server's config file) attempts to enter your password.
    - If you fail to enter the correct password within the specified attempts, you will be disconnected.
    - If you succeed, you will be connected to the chat room.

2. **Chat Interaction:**
    - Authorized users can see chat history.
    - Once you are connected, you can send messages to the chat room.
    - To exit, simply type "exit" and press Enter.
    - To change your name (login), you can simply write while chatting in the chat console "Change_my_name: " + YourNewName (YourNewLogin). 

## Config Files

Config files are located in the `cfg/` folder. Each file contains descriptions of the variables, which are provided as comments within the files.

Feel free to modify the configuration settings to customize the behavior of your chat room project.

Enjoy using the chat room project!
