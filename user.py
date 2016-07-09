from pymongo_client import PymongoClient

class User(object):

    conn = PymongoClient()

    # Create collection connections
    users = conn.db['users']
    sessions = conn.db['sessions']

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.first_name
        self.last_name
        self.status = True

    def is_authenticated(self):
        session_doc = User.sessions.find_one({ 'username' : self.username })
        print(session_doc)

        if(session_doc is not None):
            return True
        else:
            return False

    def is_active(self):
        if( status == true):
            return true
        else:
            return false

    def is_anonymous(self):
        if username is None:
            return true

        user_doc = User.users.find_one( { 'username' : self.username })
        if( user_doc is not None):
            return false
        else:
            return true

    def get_id(self):
        user_doc = User.users.find_one( { 'username' : self.username } )
        return user_doc['_id']

    def find_user(username):
        return User.users.find_one( { 'username' : username } )

    def find_user_by_id(user_id):
        return User.users.find_one( { "_id" : user_id })
