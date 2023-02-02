from flask import Flask
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from os import getenv

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = getenv("SECRET_KEY")
app.config["MONGO_URI"] = getenv("MONGO_URI")

client = MongoClient(app.config["MONGO_URI"], connectTimeoutMS=30000, socketTimeoutMS=None, connect=False,
                     maxPoolsize=1)
db = client.users

todos = db.todos
posts = db.posts

from application import routes
