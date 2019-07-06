# computer-security

## Assignment 1

### Compile

Go to `a1` directory and use command `make` to compile

### Run

#### Proof of Work

By default, the server runs at 127.0.0.1 on port 17777, and the client listens to it.

`./server.out <p_bits>`

- `p_bits`: optional, the length of P in bits, e.g. `12`, default `8`

`./client.out`

##### PoW Implementation Details

**server.cpp**:

This file contains the server code.

1. Listen to port 17777.
2. Accept the client.
3. Generate random 128-bit R and P of length `p_bits`.
4. Transmit the hex-encoded challenge to the client.
5. Wait for the response. Close the connection if it takes too long.
6. Verify the response from the client.
7. Transmit `welcome` if the response is valid. Otherwise, close the connection.

**client.cpp**:

This file contains the client code.

1. Connect to server at 127.0.0.1 on port 17777.
2. Get challenge.
3. Do proof of work.
4. Give up if it takes too long.
5. Transmit answer to the server.
6. Wait for the response.
7. Close the connection.

**custom_utils.h**:

This file contains shared helper functions.

##### PoW Disclaimer

The processing time varies, especially when `p_bits` is large, such as `16`.

#### Timing Attack

`./timing_attack.out <username> <number_of_trials> <password>`

- `username`: the username, e.g. `user1`, default `y396zhao`
- `number_of_trials`: optional, the number of trials for each letter, default `15000`
- `password`: optional, the prefix of the password, should be empty at the beginning

##### TA Usage Examples

`./timing_attack.out user1`

`./timing_attack.out user1 15000 f`

`./timing_attack.out user1 15000 fi`

##### TA Implementation Details

1. Connect to the server at 127.0.0.1 on port 10458.
2. Transmit the username.
3. Wait for 100000us.
4. Transmit current password if not empty. Return if the password is correct.
5. Iterate a large number of times for each letter to get statistics.
6. Find the next letter using 95% confidence intervals.
7. If there is overlapping between the chosen letter and any other letter, stop and report. Otherwise, append the chosen letter to the password.
8. Go back to step 4.

##### TA Disclaimer

Since 95% confidence intervals are used to determine the letter, there is uncertainty especially when cracking the last letter of the password.

### Acknowledgement

Collaborated with *Liang-Hsuan Ma* (`l63ma`).
