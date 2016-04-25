from flask import request, url_for
from flask.ext.api import FlaskAPI, status, exceptions
from flask import abort
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
import requests
import json
from keys import *

random_generator = Random.new().read
#RSA Pickles will be made and saved.
merchant = RSA.generate(2048, random_generator)
paymentgateway = RSA.generate(2048, random_generator)
bank = RSA.generate(2048, random_generator)

app = FlaskAPI(__name__)

app.route("/start", methods=["POST"])

def start():
	if not request.json:
		abort(400)

	if not request.json.has_key('pi') and request.json.has_key('authrequest'):
		return 'error'

	if request.json['authrequest'] != 'hi this guy wants to transact':
		return 'error'

	return {'authresponse': 'cool, here is my certificate', 'bankcertificate': 'hello'}


app.route("/password", methods=["POST"])
def password():
	if not request.json:
		abort(400)

	if not request.json.has_key('encryptedpassword') and request.json.has_key('authdata'):
		return {'authdata' : 'error'}

	if request.json['authdata'] != 'hello':
		return {'authdata': 'authdata corrupted'}

	password = bank.decrypt(encryptedpassword)
	pass_hash = SHA512.new(password).hexdigest()

	#sub with passs hash
	if pass_hash != 'adjiaosdjsioadjasiodjasiodjasiod':
		return {'authdata': 'passwords dont match'}

	return {'authdata': 'the passwords match'}

app.route("/password", methods=["POST"])
def password():
	if not request.json:
		abort(400)

	if not request.json.has_key('encrypted_otp') and request.json.has_key('authdata'):
		return {'authdata' : 'error'}

	if request.json['authdata'] != 'hello':
		return {'authdata': 'authdata corrupted'}

	password = bank.decrypt(encryptedpassword)

	#sub with passs hash
	if password != '123123':
		return {'authdata': 'otp dont match'}

	return {'authdata': 'the otp matches'}

app.run(debug=True, port = 8003)