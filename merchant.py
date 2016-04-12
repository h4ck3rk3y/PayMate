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