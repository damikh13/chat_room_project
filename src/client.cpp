#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include "TSQueue.h"

// HEADER FILES
#include "ChatRoom.h"
#include "ConfigParser.h"
#include "Logger.h"
#include "Message.h"
#include "User.h"
#include "TSQueue.h"

int main()
{
    // ---------------------------------------------------------------------------
    // TODO: authorization
    std::string username;
    std::string password;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // LOGGING
    Logger logger(Logger::log_level::DEBUG, username);
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // CONNECTION
    // Create a client socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    bool socket_created = (client_socket != -1);
    if (!socket_created)
    {
        logger.log(Logger::log_level::ERROR, "Error creating client socket");
        return 1;
    }
    // Set up the server address structure
    struct sockaddr_in server_address_info;
    server_address_info.sin_family = AF_INET;
    server_address_info.sin_port = htons(2025);
    server_address_info.sin_addr.s_addr = inet_addr("127.0.0.1");  // Replace with your server's IP
    inet_pton(AF_INET, "127.0.0.1", &server_address_info.sin_addr);  // Server's IP address

    int connect_result = connect(
        client_socket,
        (struct sockaddr*)&server_address_info,
        sizeof(server_address_info)
    );
    bool connect_success = (connect_result != -1);
    if (!connect_success)
    {
        logger.log(Logger::log_level::ERROR, "Error connecting to the server");
        close(client_socket);
        return 1;
    }
    else
    {
        std::cout << "Connected to server" << std::endl;
        logger.log(Logger::log_level::DEBUG, "Connected to server");
    }
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // MESSAGE HANDLING
    // Allocate a buffer to store the server's response
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    // Create thread-safe queues for input and output messages
    TSQueue<std::string> input_queue; // for user input
    TSQueue<std::string> output_queue; // for server messages

    // Input thread
    std::thread input_thread([&input_queue, &logger]()
        {
            std::string user_input;
            while (true)
            {
                std::getline(std::cin, user_input);
                input_queue.push(user_input);
                logger.log(Logger::log_level::DEBUG, "Pushed user input \"" + user_input + "\" to input_queue");
            }
        }
    );

    // Main client logic
    while (true)
    {
        // Check for user input and send it
        bool input_available = !input_queue.empty();
        if (input_available)
        {
            std::string user_input = input_queue.pop();
            logger.log(
                Logger::log_level::DEBUG,
                "Popped user input \""
                + user_input
                + "\" from input_queue, sending to server..."
            );
            bool message_sent = (send(
                client_socket,
                user_input.c_str(),
                user_input.size(),
                0
            ) != -1);
            if (!message_sent)
            {
                logger.log(Logger::log_level::ERROR, "Error sending data");
                break;
            }
            logger.log(Logger::log_level::DEBUG, "...Sent user input to server");
        }

        // Check for server messages
        char recv_buffer[1024];
        memset(recv_buffer, 0, sizeof(recv_buffer));
        // logger.log(Logger::log_level::DEBUG, "Receiving message from server...");
        int bytes_read = recv(
            client_socket, // socket
            recv_buffer, // where to store the data
            sizeof(recv_buffer), // max number of bytes to read
            0 // flags
        );
        bool recv_success = (bytes_read != -1);
        if (!recv_success)
        {
            logger.log(Logger::log_level::ERROR, "Error receiving data from server");
            break;
        }
        else if (bytes_read > 0)
        {
            logger.log(
                Logger::log_level::DEBUG,
                "...Received message from server: \""
                + std::string(recv_buffer, bytes_read)
                + "\""
                + ", pushing to output_queue..."
            );
            std::string server_message(recv_buffer, bytes_read);
            output_queue.push(server_message);
        }

        // Display chat history
        while (!output_queue.empty())
        {
            std::string message = output_queue.pop();
            std::cout << "Received from server: " << message << std::endl;
            logger.log(Logger::log_level::DEBUG, "Displayed message from server: " + message);
        }
    }

    // Close the socket and join the input thread
    close(client_socket);
    input_thread.join();

    return 0;
}