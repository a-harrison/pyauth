import pymongo 
import ConfigParser

class PymongoClient(object):
    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.read('db.config')
        MONGODB_URI = config.get('DB', 'MONGODB_URI')

        self.client = pymongo.MongoClient(MONGODB_URI)
        self.db = self.client.get_default_database()

    def close(self):
        self.client.close()

    def get_db(self):
        return self.db
