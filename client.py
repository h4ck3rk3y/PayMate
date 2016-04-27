from flask import request, url_for
from flask.ext.api import FlaskAPI, status, exceptions
from flask import abort
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto import Random
import requests
import json
from keys import *


app = FlaskAPI(__name__)



@app.route('/')
def api_root():
    return 'Welcome'

def message_digest(order_information, payment_information):
	key = Random.get_random_bytes(16)
	iv = Random.get_random_bytes(16)
	oimd = SHA512.new(order_information).hexdigest()
	pimd = SHA512.new(payment_information).hexdigest()
	pomd = SHA512.new(oimd + pimd).hexdigest()
	unencrypted_digest = pomd
	aes = AES.new(key, AES.MODE_CFB, iv)
	pomd = aes.encrypt(pomd)
	return pomd, key, iv, oimd, pimd, unencrypted_digest

@app.route("/newtransaction", methods=['POST'])
def start_transaction():
	if not request.json or not request.json.has_key('OI') or not request.json.has_key('PI'):
		abort(400)

	order_information = request.json['OI']
	payment_information = request.json['PI']


	pomd, k1, iv1, oimd, pimd, unencrypted_digest = message_digest(order_information, payment_information)
	merchant_publickey = merchant.publickey()
	paymentgateway_publickey = paymentgateway.publickey()
	bank_publickey = bank.publickey()

	#pomd2 generated for merchant
	k2 = Random.get_random_bytes(16)
	iv2 = Random.get_random_bytes(16)
	aes = AES.new(k2, AES.MODE_CFB, iv2)
	pomd2 = aes.encrypt(unencrypted_digest)

	#payment gateway
	iv3 = Random.get_random_bytes(16)
	aes = AES.new(k2, AES.MODE_CFB, iv3)

	block1 = payment_information + pomd2 + oimd
	block1 = aes.encrypt(block1)
	encrypted_k2 = paymentgateway_publickey.encrypt(k2)

	#merchant
	iv4 = Random.get_random_bytes(16)
	aes = AES.new(k1, AES.MODE_CFB, iv4)
	block2 = order_information + pomd + pimd
	block2 = aes.encrypt(block2)
	encrypted_k1 = merchant_publickey.encrypt(k1)

	print data

	response = requests.post("http://localhost:8001/start/", data = json.dumps({'block1': block1,
		'block2': block2, 'iv1': iv1, 'iv2': iv2, 'iv3':iv3, 'iv4': iv4,
		'k1': encrypted_k1, 'k2': encrypted_k2}))

	data = response.json()
	bank_certificate = data['certificate']
	encrypt_auth_data = data['authdata']
	signed_auth_data = data['signature']
	auth_data_iv = data['iv']

	aes = AES.new(k1, AES.MODE_CFB, auth_data_iv)
	auth_data = aes.decrypt(encrypt_auth_data)

	if merchant_publickey.verify(SHA512.new(auth_data).hexdigest(), signed_auth_data) == False:
		return {'status': "couldnt verify merchants response"}

	if auth_data != 'everything is good':
		return {'status': 'something went wrong while starting transaction'}

	if not bank_certificate:
		return {'status': 'couldnt verify bank certificate'}

	# Customer has started his work, things have been verified.

	return {'status': 'first_phase_done', 'message': 'please send your password'}


@app.route("/password", methods=['POST'])
def password():
	if not request.json or not request.json.has_key('password'):
		abort(400)

	password = request.json['password']
	bank_publickey = bank.publickey()
	paymentgateway_publickey = paymentgateway.publickey()
	merchant_publickey = merchant.publickey()

	encrypted_password = bank_publickey.encrypt(password)
	encrypted_hash = SHA512.new(encrypted_password).hexdigest()
	block1 = encrypted_password + encrypted_hash

	k5 = Random.get_random_bytes(16)
	iv1 = Random.get_random_bytes(16)
	aes = AES.new(k5, AES.MODE_CFB, iv1)

	block1 = aes.encrypt(block1)
	encrypted_k5 = paymentgateway_publickey.encrypt(k5)

	authdata = "hi this is my password"
	hased_authdata = SHA512.new(authdata).hexdigest()
	block2 = authdata + hased_authdata

	k6 = Random.get_random_bytes(16)
	iv2 = Random.get_random_bytes(16)
	aes = AES.new(k6, AES.MODE_CFB, iv2)

	block2 = aes.encrypt(block2)
	encrypted_k6 = merchant_publickey.encrypt(k6)

	response = requests.post("http://localhost:8001/password", data = {'k5': encrypted_k5, 'k6': encrypted_k6,
		'block1': block1, 'block2': block2, 'iv2': iv, 'iv1': iv})

	data = response.json()
	encrypt_auth_data = data['authdata']
	signed_auth_data = data['signature']
	auth_data_iv = data['iv']

	aes = AES.new(k6, AES.MODE_CFB, auth_data_iv)
	auth_data = aes.decrypt(encrypt_auth_data)

	if merchant_publickey.verify(SHA512.new(auth_data).hexdigest(), signed_auth_data) == False:
		return {'status': "couldnt verify merchants response"}

	if auth_data != 'everything is good':
		return {'status': 'wrong password try again'}

	return {'status': 'first_phase_done', 'message': 'please send your OTP'}

@app.route("/otp", methods=['POST'])
def send_otp():
	if not request.json or not request.json.has_key('OTP'):
		abort(400)

	otp = request.json['OTP']
	bank_publickey = bank.publickey()
	paymentgateway_publickey = paymentgateway.publickey()
	merchant_publickey = merchant.publickey()

	encrypted_otp = bank_publickey.encrypt(encrypted_otp)
	hash_otp = SHA512.new(encrypted_otp).hexdigest()

	k9 = Random.get_random_bytes(16)
	iv1 = Random.get_random_bytes(16)
	aes = AES.new(k9, AES.MODE_CFB, iv1)

	block1 = encrypted_otp + hash_otp

	encrypted_block1 = aes.encrypt(block1)
	encrypted_k9 = paymentgateway_publickey.encrypt(k9)

	k10 = Random.get_random_bytes(16)
	iv2 = Random.get_random_bytes(16)
	aes = AES.new(k9, AES.MODE_CFB, iv2)

	auth_data = "here is my otp"
	hash_auth_data = SHA512.new(auth_data).hexdigest()
	encrypted_block2 = aes.encrypt(hash_auth_data + auth_data)

	encrypted_k10 = merchant_publickey.encrypt(k10)

	response = requests.post('http://localhost:8001', data = {'block1': encrypted_block1,
		'block2': encrypted_block2, 'iv1': iv1, 'iv2': 'iv2', 'k9': encrypted_k9,
		'k10': encrypted_k10})

	data = response.json()
	encrypt_auth_data = data['authdata']
	signed_auth_data = data['signature']
	auth_data_iv = data['iv']

	aes = AES.new(k6, AES.MODE_CFB, auth_data_iv)
	auth_data = aes.decrypt(encrypt_auth_data)


	if merchant_publickey.verify(SHA512.new(auth_data).hexdigest(), signed_auth_data) == False:
		return {'status': "couldnt verify merchants response"}

	if auth_data != 'everything is good':
		return {'status': 'wrong otp try again'}


	return {'status': 'done', 'message': 'your transaction was succesfull'}


app.run(debug=True, port=8000)