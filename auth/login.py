

import os
import sys
import jwt
import datetime
from redis import StrictRedis
from eve_auth_jwt import JWTAuth
from commons.auth import hash_password, verify_password

reload(sys)
sys.setdefaultencoding("utf-8")

from flask import Blueprint, jsonify, request, abort, current_app, make_response

auth = Blueprint('auth', __name__)

app = current_app


def abort_json(message,status):
    abort(make_response(jsonify(message=message), status))

@auth.route('/register', methods=['POST'])
def register():
    print request.json
    mail = request.json.get('mail')
    password = request.json.get('password')
    print(mail)
    print(password)

    if not mail or not password:
        abort_json("check your input", 400)

    request.json['hash_password'] = hash_password(request.json['password'])
    del request.json['password']

    accounts = app.data.driver.db['accounts']
    user = accounts.find_one({'mail': mail})
    if user:
        abort_json("user exist! ", 501)
    print user

    user = {
        "username": mail,
        "mail": mail,
        "hashpassword": request.json['hash_password']
    }

    accounts.insert(user)
    status="success"
    message="register success"
    return jsonify(status=status, messag=message)



@auth.route('/login', methods=['POST','GET'])
def login():
    if request.method == 'GET':
        return jsonify({"status": "use a get method"})
    if request.method == 'POST':
        username = request.json.get('userName') or request.json.get('mail')
        password = request.json.get('password')
        remember = request.json.get('remember')

        if not username or not password:
            abort(404)

        accounts = app.data.driver.db['accounts']
        user = accounts.find_one({'mail': username})
        #print user
        if not user:
            status = "error"
            message = "user not exist"
            return jsonify(status=status,messag=message)

        if not verify_password(password, user['hashpassword']):
            status = "error"
            message = "password invalid"
            return jsonify(status=status,messag=message)

        status = "ok"
        message = "login sucess"
        remember = remember
        # redis = StrictRedis()
        token = jwt.encode({
                'mail':  username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=300),
                'iss':  app.config['JWT_ISSUER'],
            },
            app.config['JWT_SECRET'],
            algorithm='HS256')
        # print token
        # decode = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        # print decode

        # redis = StrictRedis()
        # redis.set(username,token)
        #token = redis.get(username)

        return jsonify(status=status,messag=message, remember=remember, token=token, currentAuthority='admin')

