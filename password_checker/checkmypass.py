"""Uses the Pwned Passwords API to determine if a password has been exposed.

To Call Script:
    python checkmypass.py <password> <password1> <password2>
"""
from __future__ import annotations

import requests
from typing import TYPE_CHECKING
import hashlib
import sys

if TYPE_CHECKING:
    from collections import Iterable
    from requests.models import Response


def request_api_data(query_char: str) -> Response:
    """Sends the API request to determine if password/s entered have been exposed.

    Args:
        query_char: First five characters of the password in sha1 hash
    Raises:
        RuntimeError if unable to communicate with the API
    Returns:
        Response Object
    """
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res


def get_password_leaks_count(response_hash: Response, hash_to_check: str) -> int:
    """Checks the response_hash values to determine if the password hash entered by the
    user exists or not.

    Args:
        response_hash: Response object containing any hash values that start with the first five
                       characters of the password entered.
        hash_to_check: User password hash value to check

    Returns:
        Number of times the password has been exposed if the hash_to_check value is found in the response_hash,
        otherwise zero.
    """
    hashes = (line.split(':') for line in response_hash.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwn_api_check(password: str) -> int:
    """Converts the password entered into a sha1 hash and then checks to see if the
    password has been exposed through the API.

    Args:
        password: password to query the API with to determine if it has been exposed or not

    Returns:
        Zero or the number of times the password has been exposed
    """
    sha1password = hashlib.sha1(password.encode('UTF-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args: Iterable) -> str:
    """Processes each password entered by the user and checks to see if the password has been exposed.

    Args:
        args: passwords to check separated by a space in the script call

    Returns:
        'Done' once all passwords have been checked and the results outputted to the console
    """
    for password in args:
        count = pwn_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password.')
        else:
            print(f'{password} was NOT found. Carry On!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
