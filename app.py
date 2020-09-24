from flask import Flask, jsonify, request, make_response, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash,check_password_hash
from flask_jwt_extended import  JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_pymongo import PyMongo,pymongo
import os
from dotenv import load_dotenv, find_dotenv

load_dotenv()


app = Flask(__name__)
app.config['MONGO_URI'] = os.getenv("MONGO_URI")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_KEY")
mongo = PyMongo(app)

jwt = JWTManager(app)

CORS(app)

user=mongo.db.user

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

    existing_user=user.find_one({"email":email})

    if existing_user is not None:
        res={
            "message":"Existing User",
            "token":None
        }
        return make_response(jsonify(res), 200)

    token=create_access_token(identity=email)
                
    user.insert_one({"name":name,"email":email,"password":hashed_pwd})
    res={
        "message":"Sign Up successful",
        "token":token
    }
    return make_response(jsonify(res), 200)



@app.route("/login", methods=['POST'])
def find():
    email=request.json['email']
    password=request.json['password']

    user_data=user.find_one({"email":email})

    if check_password_hash(user_data["password"],password):
        msg="Logged in successfully"
        token=create_access_token(identity=email)    
    else :
        msg="Invalid Credentials"
        token = None   

    res={
        "message":msg,
        "token":token
    }
    return make_response(jsonify(res), 200)


if __name__ == "__main__":
    
    app.run(debug=True)