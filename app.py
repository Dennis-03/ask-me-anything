from flask import Flask, jsonify, request, make_response, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash,check_password_hash
from flask_jwt_extended import  JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_pymongo import PyMongo,pymongo
import os
from datetime import datetime , timedelta
from dotenv import load_dotenv, find_dotenv

load_dotenv()

app = Flask(__name__)
app.config['MONGO_URI'] = os.getenv("MONGO_URI")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_KEY")
mongo = PyMongo(app)

jwt = JWTManager(app)

CORS(app)

users=mongo.db.users
events=mongo.db.events


# JWT token expiry
expires = timedelta(days=3)
# import crud

link = "UI Link"

@app.route("/", methods=["GET"])
def home():
    return redirect(link)

@app.route("/signup", methods=['POST'])
def signup():
    name=request.json['name']
    email=request.json['email']
    password=request.json['password']
    hashed_pwd=generate_password_hash(password)

    existing_user=users.find_one({"email":email})

    if existing_user is not None:
        res={
            "message":"Existing User",
            "token":None
        }
        return make_response(jsonify(res), 200)
    
    token=create_access_token(identity=email, expires_delta=expires)
                
    users.insert_one({"name":name,"email":email,"password":hashed_pwd})
    res={
        "message":"Sign Up successful",
        "token":token
    }
    return make_response(jsonify(res), 200)



@app.route("/login", methods=['POST'])
def find():
    email=request.json['email']
    password=request.json['password']

    user_data=users.find_one({"email":email})

    if check_password_hash(user_data["password"],password):
        msg="Logged in successfully"
        token=create_access_token(identity=email, expires_delta=expires) 

    else :
        msg="Invalid Credentials"
        token = None   

    res={
        "message":msg,
        "token":token
    }
    return make_response(jsonify(res), 200)

@app.route("/user/create", methods=['POST'])
@jwt_required
def create():
    event_name=request.json['event_name']
    event_date=request.json['event_date']
    event_guest=request.json['event_guest']

    user_data=users.find_one({"email":get_jwt_identity()})

    events.insert_one({"event_name":event_name,"event_date":event_date,"event_guest":event_guest,"user_id":user_data['_id']})
    return(get_jwt_identity())

if __name__ == "__main__":
    
    app.run(debug=True)