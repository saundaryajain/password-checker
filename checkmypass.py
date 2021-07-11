import requests
import hashlib
#import sys #include if input to be given from CLI

def request_api_data(query_char):
	#query_char is the first five values of our hashed password
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}')
	return res

def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5char)
	return get_password_leaks_count(response, tail)

def main(passwords):
	result = ''
	for password in passwords:
		count = pwned_api_check(password)
		if count:
			result += f'{password} has been found {count} times. You should probably change it.\n'
		else:
			result += f'{password} was NOT found. You can use it.\n'
	return result

if __name__ == '__main__':

	#to give input from command line
	#passwords = sys.argv[1:]

	#to give input from text file
	with open('passwords.txt', 'r') as pwd:  #provide the path of input file with passwords you want to validate
		passwordsfile = pwd.read()

	passwords = passwordsfile.split('\n')

	result = main(passwords)

	with open('result.txt', 'w') as rs:
		rs.write(result)