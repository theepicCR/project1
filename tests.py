#import libraries
import pytest
import json
import re
from main import app


#testing /.well-known/jwks.json endpoint with GET method
def testJwksJsonGET():
  #checks if status code is 200, if data is valid JWK,
  #and if type is application/json
  with app.test_client() as client:
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200

    #make JWK regex to check if it matches in response
    regex = b'^{.*}\n$'
    assert re.match(regex, response.data)
    assert response.mimetype == 'application/json'


#testing /.well-known/jwks.json endpoint with POST method
def testJwksJsonPOST():
  #checks if status code is 405
  with app.test_client() as client:
    response = client.post('/.well-known/jwks.json')
    assert response.status_code == 405


#testing auth endpoint by itself with GET method
def testAuthGET():
  #checks if status code is 405
  with app.test_client() as client:
    response = client.get('/auth')
    assert response.status_code == 405


#testing auth endpoint by itself with POST method
def testAuthPOST():
  #checks if status code is 200, if data is JSON decodable,
  #and if type is application/json
  with app.test_client() as client:
    response = client.post('/auth')
    assert response.status_code == 200
    assert json.loads(response.data)
    assert response.mimetype == 'application/json'


#testing /auth endpoint with expiry parameter with GET method
def testAuthExpGET():
  #checks if status code is 405
  with app.test_client() as client:
    response = client.get('/auth?expired=true')
    assert response.status_code == 405


#testing /auth endpoint with expiry parameter with POST method
def testAuthExpPOST():
  #checks if status code is 200, if data is JSON decodable,
  #and if type is application/json
  with app.test_client() as client:
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    assert json.loads(response.data)
    assert response.mimetype == 'application/json'


#calling test functions
testJwksJsonGET()
testJwksJsonPOST()
testAuthGET()
testAuthPOST()
testAuthExpGET()
testAuthExpPOST()
