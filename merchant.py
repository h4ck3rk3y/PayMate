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
def first_message():
	if not request.json:
		abort(400)

	paymentgateway_publickey = paymentgateway.publickey()
	bank_publickey = bank.publickey()

	encrypted_pi = request['block1']
	encrypted_oi = request['block2']
	iv1 = request['iv1']
	iv2 = request['iv2']
	iv3 = request['iv3']
	iv4 = request['iv4']
	k1 = request['k1']
	k2 = request['k2']

	encrypted_k2 = merchant.decrypt(k2)
	aes = AES.new(k2, AES.MODE_CFB, iv4)
	oi = aes.decrypt(encrypted_oi)
	aes = AES.new(k2, AES.MODE_CFB, iv1)
	pimd =  oi[-128:]
	pomd =  aes.decrypt(oi[-256:-128])
	oi = oi[:-256]

	oimd = SHA512.new(oi).hexdigest()
	our_pomd = SHA512.new(oimd + pimd).hexdigest()

	if our_pomd != pomd:
		return 'message went wrong during transmission, hashes dont match'

	authdata = 'hi here is the payment information'
	k3 = Random.get_random_bytes(16)
	iv5 = Random.get_random_bytes(16)
	aes = AES.new(k3, AES.MODE_CFB, iv5)
	encrypted_authdata = aes.encrypt(authdata)
	encrypted_k3 = paymentgateway_publickey.encrypt(k3)
	hash_authdata = merchant.sign(SHA512.new(authdata).hexdigest())

	data = {'authdata': authdata, 'k3': encrypted_k3, 'hash_authdata', 'pi': encrypted_pi, 'k1': k1, 'iv2': iv2, 'iv3': 'iv3': 'iv5': 'iv5'}
	response = requests.post('http://localhost:8002/start', data = data)

	data = response.json()
	bank_certificate = data['certificate']
	encrypt_auth_data = data['authdata']
	signed_auth_data = data['signature']
	auth_data_iv = data['iv']
	k4 = merchant.decrypt(data['k4'])

	aes = AES.new(k4, AES.MODE_CFB, auth_data_iv)
	auth_data = aes.decrypt(encrypt_auth_data)

	if paymentgateway_publickey.verify(SHA512.new(auth_data).hexdigest(), signed_auth_data) == False:
		return {'status': "couldnt verify paymentgateway response"}

	if auth_data != 'everything is good':
		return {'status': 'something went wrong while starting transaction'}

	if not bank_certificate:
		return {'status': 'couldnt verify bank certificate'}

	authdata = 'everything is goood'
	iv = Random.get_random_bytes(16)
	aes = AES.new(k1, AES.MODE_CFB, iv)
	encrypted_authdata = aes.encrypt(authdata)
	hash_authdata = merchant.sign(SHA512.new(authdata).hexdigest())

	return {'authdata': authdata, 'signature': hash_authdata, 'iv': iv, 'certificate': bank_certificate}

app.route("/password", methods=['POST'])
def password():
	if not request.json:
		abort(400)

	k5 = (request['k5'])
	k6 = merchant.decrypt(request['k6'])
	i5 = request['iv1']
	i6 = request['i5']
	block1 = request['block1']
	block2 = request['block2']

	aes6 = AES.new(k6, AES.MODE_CFB, i6)

	decrypt_block2 = aes6.decrypt(block2)
	authdata = decrypt_block2[:-128]
	hash_authdata = decrypt_block1[-128:]

	if SHA512.new(authdata).hexdigest() != hash_authdata:
		return 'hash of auth doesnt match'

	authdata = 'the customer is trying to send his pass, take it'
	k7 = Random.get_random_bytes(16)
	i7 = Random.get_random_bytes(16)
	aes = Random.get_random_bytes(16)
	encrypted_authdata = aes.decrypt(authdata)
	signed_auth_data = merchant.sign(encrypted_authdata)
	encrypted_k7 = paymentgateway_publickey.encrypt(k1)

	data = {'k7': k7, 'i7': i7, 'authdata': encrypted_authdata, 'hash_authdata': hash_authdata,
	'epassword': block1, 'k5', 'i5'}

	response = requests.post('http://loclahost:8002/password', data=data)

	data = response.json()
	encrypt_auth_data = data['authdata']
	signed_auth_data = data['signature']
	auth_data_iv = data['iv']
	k4 = merchant.decrypt(data['k4'])

	aes = AES.new(k4, AES.MODE_CFB, auth_data_iv)
	auth_data = aes.decrypt(encrypt_auth_data)

	if paymentgateway_publickey.verify(SHA512.new(auth_data).hexdigest(), signed_auth_data) == False:
		return {'status': "couldnt verify paymentgateway response"}

	if auth_data != 'everything is good':
		return {'status': 'something went wrong while starting transaction'}

	auth_data = 'everything is good'
	iv = Random.get_random_bytes(16)
	aes = AES.new(k6, AES.MODE_CFB, iv)
	encrypted_authdata = aes.encrypt(auth_data)
	signature = merchant.sign(SHA512.new(signature).hexdigest())

	return {'iv': iv, 'authdata': encrypted_authdata, 'signature': signature}

app.route("/otp", methods=["POST"])
def otp():
	pass