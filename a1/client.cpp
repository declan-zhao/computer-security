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

#include "custom_utils.h"

bool process_challenge(const string &R, const string &PH, string &answer);
int socket_to_server(const char *IP, int port);

int main(int argc, char *argv[])
{
    int server_socket = socket_to_server("127.0.0.1", 17777);

    if (server_socket != -1)
    {
        struct timeval tv;

        tv.tv_sec  = 10;
        tv.tv_usec = 0;

        setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));

        // read challenge
        const string &challenge = read_packet(server_socket);
        int   slash_pos         = challenge.find('/');

        if (slash_pos != challenge.npos)
        {
            const string &R  = hex_to_string(challenge.substr(0, slash_pos));
            const string &PH = challenge.substr(slash_pos + 1, challenge.length());

            string answer;

            if (process_challenge(R, PH, answer))
            {
                cout << "Answer: " << answer << endl;

                send(server_socket, (answer + "\n").c_str(), strlen((answer + "\n").c_str()), MSG_NOSIGNAL);

                const string &result = read_packet(server_socket);
                cout << "Result: " << result << endl;

                close(server_socket);
            }
            else
            {
                close(server_socket);
            }
        }
        else
        {
            cerr << "Wrong challenge format!" << endl;
            close(server_socket);
        }
    }

    return 0;
}

bool process_challenge(const string &R, const string &PH, string &answer)
{
    int min_processing_time = get_min_processing_time();
    int max_processing_time = get_max_processing_time(PH.length() * 4);

    // start timer
    clock_t start = clock();

    string hash;
    double processing_time;

    // do PoW
    do
    {
        answer = R + generate_random_string(128) + R;

        if (!get_sha256(answer, hash))
        {
            cerr << "Cannot generate hash!" << endl;
            return false;
        }

        // stop timer
        clock_t end = clock();

        processing_time = (double)(end - start) / CLOCKS_PER_SEC;

        if (processing_time > max_processing_time)
        {
            cerr << "It takes too long!" << endl;
            return false;
        }
    } while (hash.find(PH) == hash.npos || hash.find(PH) != 0);

    cout << "Processing time: " << processing_time << "s" << endl;

    while (processing_time < min_processing_time)
    {
        usleep(500000);
        processing_time += 0.5;
    }

    answer = string_to_hex(answer);

    return true;
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
