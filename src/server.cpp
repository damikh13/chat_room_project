#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <deque>
#include <map>
#include <algorithm>
#include <thread>
#include <sstream>

// HEADER FILES
#include "Logger.h"
#include "ConfigParser.h"
#include "Message.h"
#include "User.h"
#include "TSQueue.h"

// GENERAL HELPERS
int receive_data(int client_socket, char* buffer, size_t buffer_size, std::string& received_data, Logger& logger)
{
    memset(buffer, 0, buffer_size);
    int bytes_read = recv(client_socket, buffer, buffer_size, 0);
    if (bytes_read > 0)
    {
        received_data = std::string(buffer, bytes_read);
    }
    return bytes_read;
}
inline void chat_history_push(std::deque<Message>& chat_history, const Message& message, int MAX_HISTORY_SIZE)
{
    if (chat_history.size() == MAX_HISTORY_SIZE)
    {
        chat_history.pop_front();
    }
    chat_history.push_back(message);
}
void send_data(int socket, const std::string& data, Logger& logger)
{
    std::string data_with_delimiter = data + ";";
    bool send_success = (send(socket, data_with_delimiter.c_str(), data_with_delimiter.size(), 0) != -1);
    if (!send_success)
    {
        logger.log(Logger::log_level::ERROR, "Error sending data to client");
    }
}
void split(const std::string& string_to_split, char delimiter, std::vector<std::string>& result)
{
    std::stringstream ss(string_to_split);
    std::string token;
    while (std::getline(ss, token, delimiter))
    {
        result.push_back(token);
    }
}
void remove_client(int client_socket, std::map<int, User>& connected_clients)
{
    auto it = std::find_if(connected_clients.begin(), connected_clients.end(),
        [&client_socket](const std::pair<int, User>& client)
        {
            return client.first == client_socket;
        });
    if (it != connected_clients.end())
    {
        connected_clients.erase(it);
    }
}

// HANDLE CLIENT CONNECTION HELPERS
inline int accept_client_connection(int server_socket, Logger& logger)
{
    sockaddr_in client_address_info;
    socklen_t client_address_info_size = sizeof(client_address_info);
    int client_socket = accept(
        server_socket,
        (struct sockaddr*)&client_address_info,
        &client_address_info_size
    );
    bool accept_result = (client_socket != -1);
    if (!accept_result)
    {
        logger.log(Logger::log_level::ERROR, "Error accepting client connection");
        return -1;
    }
    logger.log(Logger::log_level::DEBUG, "Client connected");
    return client_socket;
}
inline std::string receive_handshake_message(int client_socket, size_t BUFFER_SIZE, Logger& logger)
{
    std::string handshake_message;
    char recv_buffer[BUFFER_SIZE];
    int handshake_message_bytes = receive_data(client_socket, recv_buffer, BUFFER_SIZE, handshake_message, logger);
    if (handshake_message_bytes == 0)
    {
        logger.log(Logger::log_level::ERROR, "Client disconnected");
        return "Client disconnected";
    }
    else if (handshake_message_bytes == -1)
    {
        logger.log(Logger::log_level::ERROR, "Error receiving handshake message from client");
        return "";
    }
    logger.log(Logger::log_level::DEBUG, "Handshake message: \"" + handshake_message + "\"");
    return handshake_message;
}
inline std::vector<std::string> parse_handshake_message(const std::string& handshake_message)
{
    std::vector<std::string> initial_message_split;
    split(handshake_message, ':', initial_message_split);
    return initial_message_split;
}
inline bool is_username_taken(const std::string& username, const std::map<int, User>& connected_clients)
{
    for (const auto& client : connected_clients)
    {
        if (client.second.get_username() == username)
        {
            return true;
        }
    }
    return false;
}
inline void reject_client_connection(int client_socket, Logger& logger)
{
    send_data(client_socket, "Credentials already in use. Please, try again.", logger);
    close(client_socket);
}
inline std::map<std::string, std::string> read_database(Logger& logger, const std::string& DATABASE_FILE_PATH)
{
    logger.log(Logger::log_level::DEBUG, "Reading database...");
    std::ifstream database_file(DATABASE_FILE_PATH);
    if (!database_file.is_open())
    {
        logger.log(Logger::log_level::ERROR, "Error opening database file");
        return {};
    }
    std::map<std::string, std::string> database;
    std::string handshake_message;
    while (getline(database_file, handshake_message))
    {
        std::vector<std::string> handshake_message_split;
        split(handshake_message, ':', handshake_message_split);
        database[handshake_message_split[0]] = handshake_message_split[1];
    }
    database_file.close();
    logger.log(Logger::log_level::DEBUG, "...Database read");
    return database;
}
inline bool authenticate_user(const std::map<std::string, std::string>& database, const std::string& username, std::string& password, int NUM_AUTH_ATTEMPTS, int client_socket, size_t BUFFER_SIZE, Logger& logger)
{
    bool user_exists = false;

    for (int i = 0; i < NUM_AUTH_ATTEMPTS; ++i)
    {
        // Check if the username and password match the database
        logger.log(Logger::log_level::DEBUG, "Checking if user[" + username + ":" + password + "] exists...");
        user_exists = (database.find(username) != database.end() && database.at(username) == password);

        if (user_exists)
        {
            logger.log(Logger::log_level::DEBUG, "User exists");
            send_data(client_socket, "User exists. Welcome back!", logger);
            user_exists = true;
            break;
        }
        else
        {
            logger.log(Logger::log_level::DEBUG, "User does not exist, asking for new password...");
            send_data(client_socket, "User does not exist. Please, try again. Attempts left: " + std::to_string(NUM_AUTH_ATTEMPTS - i - 1), logger);

            // receive new password from client
            std::string new_handshake_message;
            char recv_buffer[BUFFER_SIZE];
            int new_handshake_message_bytes = receive_data(client_socket, recv_buffer, BUFFER_SIZE, new_handshake_message, logger);
            if (new_handshake_message_bytes == 0)
            {
                logger.log(Logger::log_level::ERROR, "Client disconnected");
                return false;
            }

            // parse the new handshake message
            std::vector<std::string> new_initial_message_split;
            split(new_handshake_message, ':', new_initial_message_split);
            password = new_initial_message_split[2];

            logger.log(Logger::log_level::DEBUG, "New password: " + password);
        }
    }

    return user_exists;
}
inline void send_chat_history(int client_socket, int chat_history_size_to_send, const std::string& client_chat_history_size_str, const std::deque<Message>& chat_history, Logger& logger)
{
    send_data(client_socket, "Chat history [" + client_chat_history_size_str + "]:", logger);
    for (int i = 0; i < chat_history_size_to_send; ++i)
    {
        send_data(client_socket, chat_history[i].to_string(), logger);
    }
    if (chat_history_size_to_send < chat_history.size())
    {
        send_data(client_socket, "Chat history is too large to send. Please, increase CHAT_HISTORY_SIZE in the config file.", logger);
    }
    send_data(client_socket, "End of chat history.", logger);
}
inline void handle_existing_user(int client_socket, User& user, int NUM_AUTH_ATTEMPTS, size_t BUFFER_SIZE, const std::string& DATABASE_FILE_PATH, Logger& logger, int chat_history_size_to_send, const std::string& client_chat_history_size, std::deque<Message>& chat_history, std::map<int, User>& connected_clients)
{
    std::string username = user.get_username();
    std::string password = user.get_password();

    std::map<std::string, std::string> database = read_database(logger, DATABASE_FILE_PATH);

    bool user_exists = authenticate_user(database, username, password, NUM_AUTH_ATTEMPTS, client_socket, BUFFER_SIZE, logger);

    if (!user_exists)
    {
        send_data(client_socket, "Too many authentication attempts. Disconnecting...", logger);
        remove_client(client_socket, connected_clients);
        close(client_socket);
    }
    else
    {
        send_chat_history(client_socket, chat_history_size_to_send, client_chat_history_size, chat_history, logger);
    }
}
inline void handle_new_user(const std::string& username, const std::string& password, const std::string& DATABASE_FILE_PATH, Logger& logger)
{
    logger.log(Logger::log_level::DEBUG, "Writing new user's info: " + username + ":" + password + " to database...");
    bool flag = true;
    std::ifstream file(DATABASE_FILE_PATH);
    std::vector<std::string> logins;
    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find(":");
        if (pos != std::string::npos) {
            std::string login = line.substr(0, pos);
            logins.push_back(login);
        }
    }
    file.close();
    for (const auto& login : logins) {
        if (login == username){
            flag = false;
            break;
       }
    }

    std::ofstream database_file(DATABASE_FILE_PATH, std::ios_base::app);
    if (!database_file.is_open())
    {
        logger.log(Logger::log_level::ERROR, "Error opening database file");
        return;
    }
    if (flag){
        database_file << username << ":" << password << std::endl;
        logger.log(Logger::log_level::DEBUG, "...New user's info written to database");
    }
    database_file.close();
}
inline void create_client_thread(const int& client_socket, TSQueue<Message>& output_queue, Logger& logger, std::map<int, User>& connected_clients, std::deque<Message>& chat_history, const size_t& BUFFER_SIZE, const int& MAX_HISTORY_SIZE, const std::string& DATABASE_FILE_PATH)
{
    logger.log(Logger::log_level::DEBUG, "Creating client thread...");
    std::thread client_thread([client_socket, &output_queue, &logger, &connected_clients, &chat_history, &BUFFER_SIZE, &MAX_HISTORY_SIZE, &DATABASE_FILE_PATH]()
        {
            char recv_buffer[BUFFER_SIZE];

            std::string message_content;
            while (true)
            {
                int received_message_bytes = receive_data(client_socket, recv_buffer, BUFFER_SIZE, message_content, logger);

                // Check if the client disconnected
                // it's either if the received message is empty or if the received message is 'exit'
                bool client_disconnected = (received_message_bytes == 0 || message_content == "exit");
                if (client_disconnected)
                {
                    logger.log(Logger::log_level::ERROR, "Client disconnected");
                    Message message("exit", connected_clients[client_socket].get_username());
                    output_queue.push(message);

                    message.set_content("Client [" + message.get_sender() + "] disconnected.");
                    message.set_sender("server");
                    chat_history_push(chat_history, message, MAX_HISTORY_SIZE);
                    break;
                }
                else if (received_message_bytes == -1)
                {
                    continue;
                }else if (message_content.find("Change_my_name: ") == 0){
                    std::string cur_user = connected_clients[client_socket].get_username();

                    std::string oldUserName = cur_user;

                    std::string newUserName = message_content;
                    newUserName.erase(0, std::string("Change_my_name: ").length());
            
                    std::ifstream inputFile(DATABASE_FILE_PATH);

                    std::ofstream outputFile("temp.txt");
                    if (!outputFile.is_open()) {
                        std::cerr << "Failed to create a temporary file." << std::endl;
                        return 1;
                    }

                    std::string line;
                    while (std::getline(inputFile, line)) {
                        size_t pos = line.find(':');
                        if (pos != std::string::npos) {
                            std::string currentName = line.substr(0, pos);
                            if (currentName == oldUserName) {
                                outputFile << newUserName << line.substr(pos) << std::endl;
                                continue;
                            }
                        }
                        outputFile << line << std::endl;
                    }

                    outputFile.close();

                    if (std::rename("temp.txt", DATABASE_FILE_PATH.c_str()) != 0) {
                        std::cerr << "Failed to replace file." << std::endl;
                        return 1;
                    }

                    // Change usernamme in connected_clients map:
                    for (auto& current_client : connected_clients)
                    {
                        if (current_client.second.get_username() == oldUserName)
                        {
                            current_client.second.set_username(newUserName);
                        }
                    }
                    std::string info_message_content = "client[" + oldUserName + "]" "changed their name to " + newUserName;
                    Message info_message(info_message_content, "server");
                    output_queue.push(info_message);
                    continue;
                }
                logger.log(Logger::log_level::DEBUG, "Received message from client: " + message_content);
                Message message(message_content, connected_clients[client_socket].get_username());
                output_queue.push(message);
                chat_history_push(chat_history, message, MAX_HISTORY_SIZE);
            }
        });
    client_thread.detach(); // detach the client thread so it can run independently
}

// CONNECTION HELPERS
inline int create_server_socket(Logger& logger)
{
    logger.log(Logger::log_level::DEBUG, "Creating server socket...");
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        logger.log(Logger::log_level::ERROR, "Error creating server socket");
    }
    else
    {
        logger.log(Logger::log_level::DEBUG, "...Server socket created");
    }
    return server_socket;
}
inline bool bind_server_socket(int server_socket, int PORT_NUMBER, Logger& logger)
{
    logger.log(Logger::log_level::DEBUG, "Binding server socket...");
    sockaddr_in server_address_info;
    server_address_info.sin_family = AF_INET;
    server_address_info.sin_port = htons(PORT_NUMBER);
    server_address_info.sin_addr.s_addr = INADDR_ANY;
    int bind_result = bind(server_socket, (struct sockaddr*)&server_address_info, sizeof(server_address_info));
    if (bind_result == -1)
    {
        logger.log(Logger::log_level::ERROR, "Error binding server socket");
        close(server_socket);
        return false;
    }
    else
    {
        logger.log(Logger::log_level::DEBUG, "...Server socket bound");
        return true;
    }
}
inline bool start_listening(int server_socket, int MAX_CLIENTS, Logger& logger)
{
    logger.log(Logger::log_level::DEBUG, "Listening on server socket...");
    int listen_result = listen(server_socket, MAX_CLIENTS);
    if (listen_result == -1)
    {
        logger.log(Logger::log_level::ERROR, "Error listening on server socket");
        close(server_socket);
        return false;
    }
    else
    {
        logger.log(Logger::log_level::DEBUG, "...Server socket listening");
        return true;
    }
}

// MAIN LOGIC HELPERS
inline void handle_server_input(TSQueue<Message>& input_queue, Logger& logger) // Function to handle server input (e.g., commands)
{
    std::string server_input;
    while (true)
    {
        std::getline(std::cin, server_input);
        logger.log(Logger::log_level::DEBUG, "Server input: " + server_input);
        Message server_message(server_input, "server");
        input_queue.push(server_message);
    }
}
inline void handle_server_output(TSQueue<Message>& output_queue, std::map<int, User>& connected_clients, Logger& logger) // Function to handle server output (e.g., messages to clients)
{
    while (true)
    {
        if (!output_queue.empty())
        {
            Message message = output_queue.pop();
            bool client_disconnected = (message.get_content() == "exit");
            if (client_disconnected)
            {
                auto it = std::find_if(connected_clients.begin(), connected_clients.end(),
                    [&message](const std::pair<int, User>& client)
                    {
                        return client.second.get_username() == message.get_sender();
                    });
                if (it != connected_clients.end())
                {
                    connected_clients.erase(it);
                }
                message.set_content("Client [" + message.get_sender() + "] disconnected.");
                message.set_sender("server");
            }
            logger.log(Logger::log_level::DEBUG, "Broadcasting message: " + message.to_string() + "...");
            for (const auto& client : connected_clients)
            {
                bool same_client = (client.second.get_username() == message.get_sender());
                if (same_client)
                {
                    continue;
                }
                send_data(client.first, message.to_string(), logger);
                logger.log(Logger::log_level::DEBUG, "...Message broadcasted to client " + std::to_string(client.first));
            }
        }
    }
}
inline void handle_client_connection(int server_socket, TSQueue<Message>& output_queue, std::map<int, User>& connected_clients, Logger& logger, std::deque<Message>& chat_history, size_t BUFFER_SIZE, int MAX_HISTORY_SIZE, int NUM_AUTH_ATTEMPTS, const std::string& DATABASE_FILE_PATH) // Function to handle client connection
{
    while (true)
    {
        int client_socket = accept_client_connection(server_socket, logger);
        if (client_socket == -1)
        {
            continue;
        }

        // Receive handshake message from client
        std::string handshake_message = receive_handshake_message(client_socket, BUFFER_SIZE, logger);
        if (handshake_message.empty())
        {
            continue;
        }
        else if (handshake_message == "Client disconnected")
        {
            close(client_socket);
            continue;
        }

        // Parse handshake message
        std::vector<std::string> initial_message_split = parse_handshake_message(handshake_message);
        const std::string& new_or_existing_user = initial_message_split[0];
        const std::string& username = initial_message_split[1];
        std::string& password = initial_message_split[2]; // can be either the initial password or the new password
        const std::string& client_chat_history_size_str = initial_message_split[3];

        if (is_username_taken(username, connected_clients))
        {
            reject_client_connection(client_socket, logger);
            continue;
        }

        // Add the client to the connected_clients map
        connected_clients[client_socket] = User(username, password);
        logger.log(Logger::log_level::DEBUG, "Client connected: " + username + ":" + password);
        Message connected_info_message("Client [" + username + "][" + new_or_existing_user + "] connected.", "server");

        // Get chat history size to send
        int cilent_chat_history_size = std::stoi(client_chat_history_size_str);
        int chat_history_size = static_cast<int>(chat_history.size());
        int chat_history_size_to_send = std::min(cilent_chat_history_size, chat_history_size);


        if (new_or_existing_user == "existing_user")
        {
            handle_existing_user(client_socket, connected_clients[client_socket], NUM_AUTH_ATTEMPTS, BUFFER_SIZE, DATABASE_FILE_PATH, logger, chat_history_size_to_send, client_chat_history_size_str, chat_history, connected_clients);
        }
        else if (new_or_existing_user == "new_user")
        {
            handle_new_user(username, password, DATABASE_FILE_PATH, logger);
        }

        chat_history_push(chat_history, connected_info_message, MAX_HISTORY_SIZE);
        output_queue.push(connected_info_message); // push the message to the output_queue so it can be broadcasted to all clients

        create_client_thread(client_socket, output_queue, logger, connected_clients, chat_history, BUFFER_SIZE, MAX_HISTORY_SIZE, DATABASE_FILE_PATH);
    }
}

int main(int argc, char* argv[])
{
    // ---------------------------------------------------------------------------
    // ARGUMENT PARSING
    if (argc != 3)
    {
        std::cout << "Usage: " << argv[0] << " <config_file_path> <log_file_path>" << std::endl;
        return 1;
    }

    std::string config_file_path(argv[1]);  // Path to the config file
    std::string log_file_path(argv[2]);     // Path to the log file
    // ---------------------------------------------------------------------------


    // ---------------------------------------------------------------------------
    // LOGGING
    Logger logger(log_file_path, Logger::log_level::DEBUG); // Create a logger object
    // ---------------------------------------------------------------------------


    // ---------------------------------------------------------------------------
    // CONFIG PARSER
    ConfigParser config_parser(config_file_path, logger);

    const int MAX_CLIENTS = config_parser.get_int("MAX_CLIENTS");               // Maximum number of clients that can connect to the server simultaneously
    const int PORT_NUMBER = config_parser.get_int("PORT_NUMBER");               // Port number
    const size_t BUFFER_SIZE = config_parser.get_int("BUFFER_SIZE");            // Size of the buffer used to receive data from clients
    const int MAX_HISTORY_SIZE = config_parser.get_int("MAX_HISTORY_SIZE");     // Maximum number of messages to store in the chat history
    const int NUM_AUTH_ATTEMPTS = config_parser.get_int("NUM_AUTH_ATTEMPTS");   // Number of authentication attempts before disconnecting the client
    std::string DATABASE_FILE_PATH = config_parser.get_string("DATABASE_FILE_PATH"); // Path to the database file
    // ---------------------------------------------------------------------------


    // ---------------------------------------------------------------------------
    // CONNECTION

    // Create a server socket
    int server_socket = create_server_socket(logger);
    if (server_socket == -1)
    {
        return 1;
    }

    // Bind the socket to an IP address and port
    bool bind_success = bind_server_socket(server_socket, PORT_NUMBER, logger);
    if (!bind_success)
    {
        return 1;
    }

    // Start listening on the server socket for incoming connections
    bool listen_success = start_listening(server_socket, MAX_CLIENTS, logger);
    if (!listen_success)
    {
        return 1;
    }
    // ---------------------------------------------------------------------------


    // ---------------------------------------------------------------------------
    // MAIN SERVER LOGIC
    TSQueue<Message> input_queue;   // for server input (e.g., commands)
    TSQueue<Message> output_queue;  // for server output (e.g., messages to clients)

    std::map<int, User> connected_clients;  // to store connected clients (key: socket, value: User object)
    std::deque<Message> chat_history;       // to store chat history

    // Input thread (for handling server input, e.g., commands)
    std::thread input_thread(handle_server_input, std::ref(input_queue), std::ref(logger));
    input_thread.detach();

    // Output thread (for broadcasting messages to clients)
    std::thread output_thread(handle_server_output, std::ref(output_queue), std::ref(connected_clients), std::ref(logger));
    output_thread.detach(); // detach the output thread so it can run independently

    while (true) // Accept incoming connections
    {
        handle_client_connection(server_socket, output_queue, connected_clients, logger, chat_history, BUFFER_SIZE, MAX_HISTORY_SIZE, NUM_AUTH_ATTEMPTS, DATABASE_FILE_PATH);
    }
    // ---------------------------------------------------------------------------

    // Close the server socket and join the input thread
    close(server_socket);
    input_thread.join(); // wait for the input thread to finish

    return 0;
}