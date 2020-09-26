from flask import Flask, jsonify, request, make_response, redirect
from flask_cors import CORS

from werkzeug.security import generate_password_hash,check_password_hash
from flask_jwt_extended import  JWTManager, jwt_required, create_access_token, get_jwt_identity
import uuid

from flask_pymongo import PyMongo,pymongo
from bson.objectid import ObjectId

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

# Mongo DB Tables
users=mongo.db.users
questions=mongo.db.questions
events=mongo.db.events
attendees=mongo.db.attendees

# JWT token expiry
expires = timedelta(days=3)

link = "UI Link"

# -----------------------------------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return redirect(link)

# -----------------------------------------------------------------------------------------------------


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
                    
    new_user=users.insert_one({"name":name,"email":email,"password":hashed_pwd})
    token=create_access_token(identity=str(new_user.inserted_id), expires_delta=expires)
    
    res={
        "message":"Sign Up successful",
        "token":token
    }

    return make_response(jsonify(res), 200)



@app.route("/login", methods=['POST'])
def login():

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


@app.route("/user/create-event", methods=['POST'])
@jwt_required
def create_events():

    event_name=request.json['event_name']
    event_date=request.json['event_date']
    event_guest=request.json['event_guest']
    guest_pass=str(uuid.uuid1())

    events.insert_one({"event_name":event_name,"event_date":event_date,"event_guest":event_guest,"guest_pass":guest_pass,"user_id":ObjectId(get_jwt_identity())})

    res={
        "message":"Event Created Successfully",
    }

    return make_response(jsonify(res), 200)


@app.route("/user/all-events", methods=['GET'])
@jwt_required
def get_events():    
    
    user_events=events.find({"user_id":ObjectId(get_jwt_identity)})

    all_events=[]

    for event in user_events:
        details={
            "event_id":str(event['id']),
            "event_name":event['event_name'],
            "event_date":event['event_date'],
            "event_guest":event['event_guest']
        }
        all_events.append(details)

    res={
        "events":all_events,
        "no_of_events":len(all_events)
    }

    return make_response(jsonify(res), 200)


@app.route("/user/event-details/<event_id>", methods=['GET'])
@jwt_required
def get_event_details(event_id):    

    event_detail=events.find_one({"_id":ObjectId(event_id)})
    all_user_questions=questions.find({"event_id":ObjectId(event_id)})

    all_questions=[]

    for question in all_user_questions:
        details={
            "question_id":str(question['_id']),
            "question":question['question'],
            "answer":question['answer'],
            "attendee_name":question['attendee_name']
        }
        all_questions.append(details)

    res={
        "event_id":event_id,
        "event_name":event_detail['event_name'],
        "event_date":event_detail['event_date'],
        "event_guest":event_detail['event_guest'],
        "guest_pass":event_detail['guest_pass'],
        "questions":all_questions,
        "no_of_questions":len(all_questions)
    }

    return make_response(jsonify(res), 200)


@app.route("/attendee/create-question/<event_id>", methods=['POST'])
def create_questions(event_id):

    attendee_name=request.json['attendee_name']
    attendee_email=request.json['attendee_email']
    question=request.json['question']
    answer=""

    questions.insert_one({"attendee_name":attendee_name,"attendee_email":attendee_email,"question":question,"answer":answer,"event_id":ObjectId(event_id)})
    
    res={
        "message":"Question Added Successfully",
    }

    return make_response(jsonify(res), 200)


@app.route("/attendee/view-question/<event_id>", methods=['POST'])
def attendee_view_questions(event_id):

    attendee_email=request.json['attendee_email']
    
    user_questions=questions.find({"attendee_email":attendee_email,"event_id":ObjectId(event_id)})
    
    all_questions=[]
    for question in user_questions:
        details={
            "id":str(question["_id"]),
            "question":question["question"],
            "answer":question["answer"]
        }
        all_questions.append(details)
    
    res={
        "questions":all_questions,
        "no_of_questions":len(all_questions)
    }

    return make_response(jsonify(res), 200)


@app.route("/guest/view-question/<event_id>/<guest_pass>", methods=['GET'])
def guest_view_questions(event_id,guest_pass):

    event_detail=events.find_one({"_id":ObjectId(event_id)})

    if(event_detail['guest_pass']!=guest_pass):
        res={
        "message":"You can't view the questions",
        }
        return make_response(jsonify(res), 200)
        
    all_user_questions=questions.find({"event_id":ObjectId(event_id)})

    all_questions=[]

    for question in all_user_questions:
        details={
            "question_id":str(question['_id']),
            "question":question['question'],
            "answer":question['answer'],
            "attendee_name":question['attendee_name']
        }
        all_questions.append(details)

    res={
        "event_id":event_id,
        "event_name":event_detail['event_name'],
        "event_date":event_detail['event_date'],
        "event_guest":event_detail['event_guest'],
        "guest_pass":event_detail['guest_pass'],
        "questions":all_questions,
        "no_of_questions":len(all_questions)
    }

    return make_response(jsonify(res), 200)


# @app.route("/guest/answer-question/<event_id>/<guest_pass>", methods=['PUT'])
@app.route("/guest/answer-question", methods=['PUT'])
def guest_answer_questions():

    answer=request.json['answer']
    question_id=request.json['question_id']

    question_detail=questions.update_one({"_id":ObjectId(question_id)},{"$set":{"answer":answer}})

    # update_answer={"$set":{"answer":answer}}


    res={
        "message":"Updated successfully",
    }

    return make_response(jsonify(res), 200)

if __name__ == "__main__":
    
    app.run(debug=True)