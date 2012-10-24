#!/usr/bin/env python
#
# File to allow hashing of passwords for blog

import string
import hashlib
import random
import hmac

COOKIE_SECRET = "NomNomNomMeLoveCookies"

def make_cookie_hash(s):
	cookie_hash = hmac.new(COOKIE_SECRET,s).hexdigest()
	return "%s|%s" % (s,cookie_hash)

def check_cookie_hash(h):
	if h is None:
		return None
		
	hash_idx = h.find('|')
	if hash_idx == -1:
		return None

	val = h[:hash_idx]
	if make_cookie_hash(val) == h:
		return val

def make_salt(num_char):
	#creates salt with length num_char (input)
	return ''.join(random.choice(string.ascii_letters) for x in range(num_char))

def make_pw_hash(name,pw,salt = None):
	if salt is None:
		salt = make_salt(10)
	pw_hash = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (pw_hash,salt)

def check_pw_hash(name,pw, pw_hash):
	comma_num = pw_hash.find('|')
	if comma_num == -1:
		return False
	salt = pw_hash[comma_num+1:]
	return make_pw_hash(name,pw,salt) == pw_hash