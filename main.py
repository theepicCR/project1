 #---------------------------IMPORT LIBRARIES----------------------------
#for JWT & JWK generation
import base64

#for RSA key pair & JWT generation
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

#for kid generation
import string
import random

#for RESTful http server
from flask import Flask, request, Response
from flask_restful import Resource, Api
import json


#-------------------------GLOBAL VARIABLES-------------------------
#JWKs - expired and unexpired
keys = {"keys": []}
JWKids = {}
expired_keys = {"keys": []}

#---------------------------RSA KEYS SETUP--------------------------
def GenerateRSAkeys():
  #generate private and public keys
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

  public_key = private_key.public_key()

  return private_key, public_key

#---------------------------JWK SETUP----------------------------
def GenerateJWK(public_key, keyID, expired):
  #checks if an expired or unexpired JWK is requested
  if expired:
    expiration = 1708355887
  else:
    #expires in about a year
    expiration = 1739978287

  
  #generate n modulus
  #public_key -> int -> bytes -> base64 -> string
  n = public_key.public_numbers().n
  n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
  n_encoded = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')


  #construct the jwk manually :(
  JWK = {
    "kid": keyID, 
    "kty": "RSA", 
    "e": "AQAB", 
    "n": n_encoded,
    "alg": "RS256",
    "iat": 1708355887,
    "exp": expiration
  }

  return JWK

#---------------------------KID SETUP----------------------------
def GenerateKID():
  #generates a random Key ID (kid) of length 10
  keyID = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))

  return keyID

#---------------------------JWT SETUP----------------------------
def GenerateJWT(private_key, keyID, expired):
  #checks if an expired or unexpired JWT is requested
  if expired:
    expiration = 1708355887
  else:
    #expires in about a year
    expiration = 1739978287

  #header
  JWTheader = {
    "kid": keyID,
    "alg": "RS256",
    "typ": "JWT"
  }

  #payload
  JWTpayload = {
    "iat:": 1708355887,
    "exp": expiration
    }

  #encoding header
  #transforms to bytes to base64
  header_bytes = json.dumps(JWTheader).encode("utf-8")
  encoded_header = base64.urlsafe_b64encode(header_bytes).decode("utf-8")

  #encoding payload
  payload_bytes = json.dumps(JWTpayload).encode("utf-8")
  encoded_payload = base64.urlsafe_b64encode(payload_bytes).decode("utf-8")

  #encodes signature part of JWT
  #signs it with private key
  signature = private_key.sign((encoded_header + "." + encoded_payload).encode(), padding.PKCS1v15(), hashes.SHA256())
  encoded_signature = base64.urlsafe_b64encode(signature).decode("utf-8")

  #gets rid of the '==' padding
  encoded_signature = encoded_signature.rstrip("=")


  return encoded_header + "." + encoded_payload + "." + encoded_signature

#---------------------------HTTP SERVER SETUP----------------------------
#Flask setup
app = Flask("JWKServer")
api = Api(app)


#RESTful JWKS endpoint setup
class HTTP(Resource):
  def get(self):
    #returns all known, unexpired JWKs
    return keys

api.add_resource(HTTP, "/.well-known/jwks.json")


#request JWK based given kid
class HTTPKid(Resource):
  def get(self, kid):
    #checks if kid is in unexpired key collection
    #returns the corresponding JWK
    for k in JWKids:
      if k == kid:
        return JWKids[k]

      #else kid is in expired key collection
      #returns 405
      else:
        return {'message': 'Key Not Allowed'}, 405

api.add_resource(HTTPKid, "/.well-known/jwks.json/<kid>")


#/auth endpoint
class HTTPAuth(Resource):
  def post(self):
    #ensures a post request is soley made to /auth without extra arguments
    if request.path == "/auth" and len(request.args) == 0:
      keyID = GenerateKID()
      private_key, public_key = GenerateRSAkeys()

      #create unexpired JWT & JWK
      JWK = GenerateJWK(public_key, keyID, False)
      JWT = GenerateJWT(private_key, keyID, False)

      #add key to JWK dictionary 'keys'
      keys["keys"].append(JWK)
      JWKids[keyID] = JWK

      return Response(JWT, status=200, mimetype="application/jwt")

    #checks if the expiry parameter is present
    #if it is, creates an expired JWT & JWK
    #returns an expired JWT
    elif request.args.get("expired") == "true":
      keyID = GenerateKID()
      private_key, public_key = GenerateRSAkeys()

      #create expired JWT & JWK
      JWK = GenerateJWK(public_key, keyID, True)
      JWT = GenerateJWT(private_key, keyID, True)

      #add key to expired key collection
      expired_keys["keys"].append(JWK)

      return Response(JWT, status=200, mimetype="application/jwt")

    #return 405 if request does not fulfill requirements
    else:
      return {'message': 'Method Not Allowed'}, 405

api.add_resource(HTTPAuth, "/auth")


#---------------------------RUNNING SERVER----------------------------
if __name__ == "__main__":
  app.run(port=8080)
