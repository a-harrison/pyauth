#!pyauth/bin/python
from flask import Flask, abort, make_response, request, jsonify
from pymongo_client import PymongoClient
from user import User
import json
import os
import hashlib
import datetime
from base64 import b64encode

# Create db connection
conn = PymongoClient()

# Create collection connections
users = conn.db['users']
sessions = conn.db['sessions']

app = Flask(__name__)

@app.route('/')
def index():
    print(json.dumps(request))
    return "Hello, World!"

@app.route('/api/users/<string:username>', methods=['GET'])
def getUser(username):
    if ('Session-Id' not in request.headers):
        abort(400)

    if( isAuthenticated(username, request.headers['Session-Id']) ):
        doc =  users.find_one({ "username" : str(username)},{ "_id":0, "username":1, "password":1, "first_name":1, "last_name":1 })

        if(doc == None):
            print('Resource not found.')
            abort(404)

        return json.dumps(doc)
    else:
        print('Or maybe not?')
        return jsonify( { 'msg' : 'Please authenticate to continue.' }), 403

@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    if not request.json or ( 'username' not in request.json ) or ( 'password' not in request.json):
        abort(400)

    user = users.find_one({"username" : str(request.json['username'])}, { "_id" : 0, "username" : 1, "password" : 1, "salt" : 1 })

    if( ( user == None ) or ( user['password'] != hash_creds(request.json['password'], user['salt']) ) ):
        return jsonify({"msg" : "Incorrect username or password."}), 200
    elif( user['password'] == hash_creds(request.json['password'], user['salt'])):
        session_id = generate_session_id(user['username'])

        return jsonify({"msg" : "Authenticated.", "session_id" : session_id }), 200
    else:
        return jsonify({"msg" : "Internal Error has occurred."}), 200


@app.route('/api/signup', methods=['POST'])
def signup():
    print(request.json)
    if not request.json or ( 'username' not in request.json ) or ( 'password' not in request.json ) or ( 'first_name' not in request.json ) or ( 'last_name' not in request.json) :
        abort(400)

    user = User.find_user(request.json['username'])
    ## doc = users.find_one({"username" : request.json['username'] })

    if doc is not None:
        return jsonify({ 'msg': 'a user with this username already exists.' }), 200

    else:
        salt = b64encode(os.urandom(512)).decode('utf-8');
        pwd_hash = hash_creds(request.json['password'], salt)
        # pwd_hash = hashlib.sha256(salt + request.json['password']).hexdigest().decode('utf-8')

        account = {
            'username' : request.json['username'],
            'password' : pwd_hash,
            'salt' : salt,
            'first_name' : request.json['first_name'],
            'last_name' : request.json['last_name']
        }

        users.insert(account)
        return jsonify({ 'msg' : 'Account created' }), 200

########################################################################################################################

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error':'Not Found'}), 400)

def hash_creds(password, salt):
    return hashlib.sha256(salt + password).hexdigest().decode('utf-8')

def generate_session_id(username):
    # Remove any existing session id's
    result = sessions.delete_many({"username" : username})
    if(result.deleted_count > 0):
        print('Sessions deleted: ' + str(result.deleted_count))

    # Create new session id
    try:
        session_id =  b64encode(os.urandom(512)).decode('utf-8')
        date_now = datetime.datetime.now()
        sessions.insert({"username" : username, "session_id" : session_id, "created_at" : date_now})
    except:
        print('Unexcepted error creating session: ')

    return session_id

def isAuthenticated(username, session_id):
    session_doc = sessions.find_one({ 'username' : username })
    print(session_doc)

    if(session_doc is not None):
        return True
    else:
        return False

if __name__ == '__main__':
    app.run(debug=True)
