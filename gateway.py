from flask import request, url_for
from flask.ext.api import FlaskAPI, status, exceptions
from flask import abort
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
import requests
import json

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

	authdata = request['authdata']
	k3 = request['k3']
	hash_authdata = request['hash_authdata']
	pi = request['pi']
	k2 = request['k2']
	iv2 = request['iv2']
	iv3 = request['iv3']
	iv5 = request['iv5']

	k2 = paymentgateway.decrypt(k2)
	aes = AES.new(k2, AES.MODE_CFB, iv3)
	pi = aes.decrypt(pi)
	oimd  = pi[-128:]
	aes = AEs.new(k2, AES.MODE_CFB, iv2)
	pomd2 = aes.decrypt(pi[-256:-128])
	payment_information = pi[:-256]

	if SHA512.new(oimd  +SHA512(payment_information)).hexdigest() != pomd2:
		return 'hashes dont match, dual signature corrupted'

	aes = AES.new(k3, AES.MODE_CFB, vi5)
	authdata = aes.decrypt(authdata)

	if SHA512.new(authdata).hexdigest() != hash_authdata:
		return 'hashes dont match'

	authrequest = "hi this guy wants to transact"

	response = requests.post("http://localhost:/8002/start", data = {'authrequest': authrequest, 'pi': pi})

	data = response.json()

	if data['authresponse'] != 'cool, here is my certificate':
		return 'error'

	if not data.has_key('bankcertificate'):
		return 'error'

	k4 = Random.get_random_bytes(16)
	iv = Random.get_random_bytes(16)
	authdata = 'everything is good'
	signature = paymentgateway.sign(SHA512.new(authdata).hexdigest())
	aes = AES.new(k4, AES.MODE_CFB, iv)
	authdata = aes.encrypt()

	data = {'authdata': authdata, 'k4': k4, 'iv': iv, 'signature': signature, 'certificate': data['certificate']}

	return data

