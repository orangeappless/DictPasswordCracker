#!/usr/bin/env python3


import crypt, sys, argparse, time


# Parse command-line arguments
parser = argparse.ArgumentParser()

parser.add_argument("-s",
                    "--shadow",
                    type=str,
                    help="Path of shadow file, containing list of users",
                    required=True)

parser.add_argument("-d",
                    "--dict",
                    type=str,
                    help="Path of dictionary wordlist",
                    required=True)      

global cmd_args
cmd_args = parser.parse_args()


def find_password(user):
    user_start_time = time.time()
    is_found = False

    # Process yescrypt hash
    # Remove everything after the colon first
    shadow_line = user.split(":")

    # Get salt
    shadow_entry = shadow_line[1]
    entry_split = shadow_entry.split("$", 4)
    salt = "$".join(entry_split[0:4]) + "$"
    passwd = entry_split[4]

    with open(cmd_args.dict) as dict_file:
        for dict_line in dict_file:
            dict_passwd = dict_line.rstrip()
            dict_passwd_hashed = crypt.crypt(dict_passwd, salt)

            if salt + passwd == dict_passwd_hashed:
                print(f"[FOUND] {user} : {dict_passwd}")
                is_found = True
                break
    
    # If no password is found
    if is_found == False:
        print(f"[NOT FOUND] {user}", end="\r")

    # Elasped time for user
    user_end_time = time.time()
    user_elapsed_time = user_end_time - user_start_time
    print(f"Elapsed time: {round(user_elapsed_time, 2)}s\n")    


def main():
    """
    Example entry in /etc/shadow:
        testuser    apple   testuser:$y$j9T$YizB0iL4moAyRB31Dz9Hb/$F4XazyyuvqeCsfg0ikd2NnCie95zWM4YDoAxj86cDZ6:19333:0:99999:7:::
    
    testuser7 has password "qwertyasdf" - should not be found with supplied dicts
    """
    users = []

    # Read contents of shadow file, and store in list
    with open(cmd_args.shadow, "r") as file:
        for line in file:
            # Skip over non-users
            if "!" in line or "*" in line:
                continue
            
            users.append(line)

    print(f"[STARTING] {len(users)} users loaded...\n")

    # Start timer for total elapsed time
    total_start_time = time.time()

    for user in users:
        find_password(user)

    total_end_time = time.time()
    total_elapsed_time = total_end_time - total_start_time

    print(f"[TOTAL TIME] {round(total_elapsed_time, 2)}s")    


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
