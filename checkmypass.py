# check how many time a password has been used
# check if your password is secure
# used for make requests like in a browser but without one
import requests
import hashlib
# Hash function - > a function that generates a value (a mix of characters) of fixed length for each input that it gets
# and that value can't be converted back or changed for any input
# this function generates the value and then convert it to an index specified to your password for localisation in
# memory. => hash tables
import sys


# TODO read passwords from a file
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # Check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should probably change your password...')
        else:
            print(f'{password} was NOT found... Carry on!')
    return 'done!'


if __name__ == '__main__':
   sys.exit(main(sys.argv[1:]))
