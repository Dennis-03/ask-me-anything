from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from flask_pymongo import PyMongo,pymongo
import os
from dotenv import load_dotenv, find_dotenv

load_dotenv()


app = Flask(__name__)
app.config['MONGO_URI'] = os.getenv("MONGO_URI")
mongo = PyMongo(app)

CORS(app)

user=mongo.db.user

# import crud

@app.route("/", methods=["GET"])
def home():
    return("URI")

@app.route("/post", methods=['POST'])
def homepost():
    name=request.json['name']
    email=request.json['email']
    password1=request.json['password1']
    print(name,email,password1)
    user.insert_one({"name":name,"email":email})
    return("working")

if __name__ == "__main__":
    
    app.run(debug=True)