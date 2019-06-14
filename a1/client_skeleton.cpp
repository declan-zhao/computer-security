/********************************************************************
 * Author : Carlos Moreno
 * Created: 2019-06
 *
 * Description:
 *
 *      This is a sample code to connect to a server through TCP.
 *      You are allowed to use this as a sample / starting point
 *      for the assignment (both problems require a program that
 *      connects to something).
 *
 *      For the most part, although the file is a .c++ file, the
 *      code is also valid C code  (with some exceptions --- pun
 *      intended! :-) )
 *
 * Copyright and permissions:
 *      This file is for the exclusive purpose of our ECE-458
 *      assignment 1, and you are not allowed to use it for any
 *      other purpose.
 *
 ********************************************************************/

#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cerrno>
using namespace std;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <wait.h>
#include <unistd.h>

int socket_to_server(const char *IP, int port);
string read_packet(int socket);

class connection_closed
{
};
class socket_error
{
};

int main()
{
    int socket = socket_to_server("127.0.0.1", 10458);
    // The function expects an IP address, and not a
    // hostname such as "localhost" or ecelinux1, etc.

    if (socket != -1)
    {
        send(socket, "user1\n", 7, MSG_NOSIGNAL);
        usleep(100000);
        send(socket, "password1\n", 11, MSG_NOSIGNAL);
        cout << "Response to password1: " << read_packet(socket) << endl;
        send(socket, "password2\n", 11, MSG_NOSIGNAL);
        cout << "Response to password2: " << read_packet(socket) << endl;
    }

    return 0;
}

int socket_to_server(const char *IP, int port)
{
    struct sockaddr_in address;

    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = inet_addr(IP);
    address.sin_port        = htons(port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (connect(sock, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        return -1;
    }

    return sock;
}

// Defined redundantly in client and server source files --- you may
// want to refactor it as a common function and use it for both.
string read_packet(int client_socket)
{
    string msg;

    const int size = 8192;
    char buffer[size];

    while (true)
    {
        int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 2, 0);
        // Though extremely unlikely in our setting --- connection from
        // localhost, transmitting a small packet at a time --- this code
        // takes care of fragmentation  (one packet arriving could have
        // just one fragment of the transmitted message)

        if (bytes_read > 0)
        {
            buffer[bytes_read]     = '\0';
            buffer[bytes_read + 1] = '\0';

            const char *packet = buffer;
            while (*packet != '\0')
            {
                msg    += packet;
                packet += strlen(packet) + 1;

                if (msg.length() > 1 && msg[msg.length() - 1] == '\n')
                {
                    istringstream buf(msg);
                    string msg_token;
                    buf >> msg_token;
                    return msg_token;
                }
            }
        }

        else if (bytes_read == 0)
        {
            close(client_socket);
            throw connection_closed();
        }

        else
        {
            cerr << "Error " << errno << endl;
            throw socket_error();
        }
    }

    throw connection_closed();
}
