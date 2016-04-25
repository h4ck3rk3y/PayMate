from Crypto.PublicKey import RSA

bank_key = open('bank.pem')

merchant_key = open('merchant.pem')

paymentgateway_key = open('payment.pem')

bank = RSA.importKey(bank_key.read())

merchant = RSA.importKey(merchant_key.read())

paymentgateway = RSA.importKey(paymentgateway_key.read())
