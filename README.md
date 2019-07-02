# computer-security

## Assignment 1

### Compile

Go to `a1` directory and use command `make` to compile

### Run

#### Timing Attack

`./timing_attack.out <username> <number_of_trials> <password>`

- `username`: the username, e.g. `user1`, default `y396zhao`
- `number_of_trials`: optional, the number of trials for each letter, default `15000`
- `password`: optional, the prefix of the password, should be empty at the beginning

##### Usage Examples

`./timing_attack.out user1`

`./timing_attack.out user1 15000 f`

`./timing_attack.out user1 15000 fi`

##### Implementation Details

1. Connect to the server at 127.0.0.1 on port 10458.
2. Transmit the username.
3. Wait for 100000us.
4. Transmit current password if not empty. Return if the password is correct.
5. Iterate a large number of times for each letter to get statistics.
6. Find the next letter using 95% confidence intervals.
7. If there is overlapping between the chosen letter and any other letter, stop and report. Otherwise, append the chosen letter to the password.
8. Go back to step 4.

##### Disclaimer

Since 95% confidence intervals are used to determine the letter, there is uncertainty especially when cracking the last letter of the password.

### Acknowledgement

Collaborated with *Liang-Hsuan Ma* (`l63ma`).
