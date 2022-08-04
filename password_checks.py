"""A script that will check if passwords have been leaked and
inform users if the password is safe to use."""

import hashlib
import sys
import requests


def request_data(query_chars):
    """requests data from the API."""
    url = 'https://api.pwnedpasswords.com/range/' + query_chars
    res = requests.get(url)
    # status code of 200 is required:
    if res.status_code != 200:
        raise RuntimeError(
            f"An error occured. status code: {res.status_code}. Check API.")
    return res


def get_leak_count(hashes, hash_to_check):
    """splits the collected hashes so the hash and the number of leaks are seperated."""
    # ensure hashes is read as text when splitting into lines.
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # compare the hash tail with the recieved responses:
    for h, count in hashes:
        if h == hash_to_check:
            return count
    # if no match, return 0.
    return 0


def api_check(password):
    """Hash the and return password using sha1"""
    sha1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5_chars = sha1_pass[:5]
    hash_tail = sha1_pass[5:]
    # to ensure request is secure, request all hash tails
    # that start with the same first 5 characters.
    response = request_data(first_5_chars)
    return get_leak_count(response, hash_tail)


def main_func(args):
    """Main function to run the entire password checking process"""
    # check passwords and inform user if passwords should be changed.
    for password in args:
        count = api_check(password)
        if count:
            print(
                f"'{password}' was leaked {count} times. "
                "I advise you to change your password.")
        else:
            print(
                f"'{password}' does not appear to have been leaked. "
                "This password is safe to use.")


if __name__ == '__main__':
    # accept passwords as passwords withon the terminal when program is run.
    # allows for multiple password checks.
    sys.exit(main_func(sys.argv[1:]))
