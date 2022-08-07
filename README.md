# Password_checker
Python script that checks if passwords are safe to use.

This script uses sha1 hashing to send and recieve passwords. 

These passwords are compared using a password checking API. To ensure further security,
only part of the sha1 hash is sent to the API. The remaining unsent part of the hash
is then compared to the hashes that are returned from the API.

If the password hash generated is matched with a hash recieved from the API,
Advice is given to the user on next steps to ensure all accounts are secure.
