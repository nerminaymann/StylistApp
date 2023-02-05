import json
import os
import random
from flask import Blueprint, request, redirect, url_for, jsonify, make_response, Flask, send_from_directory

from werkzeug.utils import secure_filename
from .models import Users, Posts, Messages, PostLike, Notifications, PostComment, Followers, Img, fullInterests, \
    userInterests, fullEvents, userEvents, fullAesthetics, userAesthetics, apperanceInfo, Bookmarks, Tips, Polls, \
    Profile, SharePost, Ratings, Stars, Voting, AppSettings, AccountSettings
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required,logout_user,current_user
from . import db,  createapp
import datetime
import jwt
from functools import wraps
import uuid
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import func


views = Blueprint("views",__name__)

@views.route('/')
def mainroute():
    return "  Welcome to our Styling App   "


       #------------------------------UPLOAD IMAGE--------------------------------


folder = 'Uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload(current_user, request, imageType):
        app = Flask(__name__)
        app.config['UPLOAD_FOLDER'] = folder
        if 'file' not in request.files:
            return jsonify({'message': 'no file part'})
            return redirect(request.url)
        pic = request.files['file']
        if not pic:
            return jsonify({'message': 'no pic uploaded'})
        if pic.filename == '':
            return jsonify({'message': 'no selected file'})
            return redirect(request.url)
        if pic and allowed_file(pic.filename):
            dateNowAsString = datetime.datetime.utcnow().strftime("%d-%m-%Y_%H_%M_%S")
            newFileName = dateNowAsString + pic.filename
            imagePath = app.config['UPLOAD_FOLDER']+ '/'+ newFileName
            filename = secure_filename(newFileName)
            mimetype = pic.mimetype
            if not os.path.exists('Uploads'):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            img = Img(img=imagePath, mimetype=mimetype, name=filename, imageType=imageType)
            db.session.add(img)
            db.session.commit()
            pic.save(imagePath)
            return img.id


def upload2(current_user, request, imageType):
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = folder

    if 'file2' not in request.files:
        return jsonify({'message': 'no file part'})
        return redirect(request.url)

    pic = request.files['file2']

    if not pic:
        return jsonify({'message': 'no pic uploaded'})

    if pic.filename == '':
        return jsonify({'message': 'no selected file'})
        return redirect(request.url)

    if pic and allowed_file(pic.filename):
        dateNowAsString = datetime.datetime.utcnow().strftime("%d-%m-%Y_%H_%M_%S")
        newFileName = dateNowAsString + pic.filename
        imagePath = app.config['UPLOAD_FOLDER'] + '/' + newFileName
        filename = secure_filename(newFileName)
        mimetype = pic.mimetype

        if not os.path.exists('Uploads'):
            os.makedirs(app.config['UPLOAD_FOLDER'])
            # imagePath = os.path.join('folder', newFileName)
            # pic.save(imagePath)

        img = Img(img=imagePath, mimetype=mimetype, name=filename, imageType=imageType)
        db.session.add(img)
        db.session.commit()

        pic.save(imagePath)

        return img.id

    # return jsonify({'img has been uploaded', 200 })

@views.route('/Uploads/<path:path>')
def static_dir(path):
    return send_from_directory("../uploads",path)

     #------------------------------LOGIN & REGISTRATION--------------------------------

@views.route('/login/<userType>',methods =['GET', 'POST'])
def login(userType):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
    if userType=="normalUser" :
      dataa = request.get_json()
      email = dataa['email']
      password = dataa['password']
      if not dataa or not email or not password:
        return make_response('could not verify', 401, "login required")
      user = Users.query.filter_by(email=email).first()
      if check_password_hash(user.password, password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=180)},
            app.config['SECRET_KEY'], algorithm="HS256")
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"] )
        if not user:
            return jsonify({'message': 'there is exist for this user'})
        return make_response( jsonify({'token' : token,'exp': '180','user_id':user.id,'username':user.username,'email':user.email}), 200)
      return make_response('could not verify', 401,"login required")
    if userType == "guestUser":
        dataa = request.get_json()
        email=dataa['email']
        password=dataa['password']
        if not dataa or not email or not password:
            return jsonify({"message":"could not verify"})

        user = Users.query.filter_by(email=email).first()
        if email == password:
            token = jwt.encode(
                {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=180)},
                app.config['SECRET_KEY'], algorithm="HS256")
            dataa = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            return make_response(jsonify({'token': token,'exp': 'minutes = 180'}), 200)


@views.route('/register/<userType>', methods=['GET','POST'])
def register(userType):
    if userType == 'normalUser' :
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
        data = request.get_json()
        email_exists = Users.query.filter_by(email=data['email']).first()
        if data['password1'] != data['password2'] :
            return jsonify({"message":'Password don\'t match!'})
        elif email_exists:
            return jsonify({"message":'User already exists'})
        elif len(data['password1']) < 6 or len(data['email']) < 6:
            return jsonify({'message' : 'Length of email or password is too short'})
        else:
            new_user = Users(public_id=str(uuid.uuid4()),email=data['email'], password=generate_password_hash(data['password1']),username=data['username'],gender=data['gender'],phoneNum=data['phoneNum'],dateOfBirth=data['dateOfBirth'],userType=userType)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            user = Users.query.filter_by(email=new_user.email).first()
            token = jwt.encode(
                {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=180)},
                app.config['SECRET_KEY'], algorithm="HS256")
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            print(token)
            print(data)
            print(user.public_id)

            if not new_user:
                return jsonify({'message': 'there is no registration for user yet'})

            return make_response(jsonify({'token': token, 'exp': '180', 'user_id':new_user.id,'username':new_user.username,"email":new_user.email,
                                          'message' : 'Registered successfully'}), 200)


    if userType == 'guestUser':
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
        dataa = request.get_json()
        ID_device_exists = Users.query.filter_by(ID_device=dataa['ID_device']).first()
        if ID_device_exists:
            return jsonify({"message":'ID Device already exists'})
        else:
            ID_device = dataa['ID_device']
            uuID = dataa['uuID']
            guestLogin = Users(public_id=str(uuid.uuid4()),email=ID_device, password=ID_device, ID_device=ID_device, uuID=uuID, userType=userType)
            db.session.add(guestLogin)
            db.session.commit()
            login_user(guestLogin)
            guestuser = Users.query.filter_by(email=guestLogin.email).first()
            token = jwt.encode(
                {'public_id': guestuser.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=180)},
                app.config['SECRET_KEY'], algorithm="HS256")
            dataa = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            return make_response(jsonify({'token': token,'exp': 'minutes = 180'}), 200)
            return jsonify({"message": "you are now using the app as a guest user"})

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
      app = Flask(__name__)
      app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
      token = None
      if 'X-Access-Tokens' in request.headers:
         token = request.headers['X-Access-Tokens']
      if not token:
         return jsonify({'message': 'a valid token is missing'})
      try:
         data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"] )
         current_user = Users.query.filter_by(public_id=data['public_id']).first()
      except:
        return jsonify({'message': 'token is invalid'})
      return f(current_user, *args, **kwargs)
   return decorator


@views.route('/User_Authentication',methods=['GET','POST'])
def User_Authentication():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'

    dataa = request.get_json()
    email = dataa['email']
    user_id = dataa['user_id']

    if not dataa or not email or not user_id:
            return make_response('could not verify', 401, "Authentication required")

    user = Users.query.filter_by(email=email,id=user_id).first()

    if user:
            token = jwt.encode(
                {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=180)},
                app.config['SECRET_KEY'], algorithm="HS256")
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

            if not user:
                return jsonify({'message': 'there is no exist for this user'})

            return make_response(jsonify(
                {'token': token, 'exp': '180', 'user_id': user.id, 'username': user.username, 'email': user.email}),
                                 200)
    return make_response('could not verify', 401, "Authentication for user required")


@views.route('/users', methods=['GET'])
def get_all_users():
    users = Users.query.all()

    result = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.email
        user_data['username'] = user.username
        user_data['gender'] = user.gender
        user_data['phoneNum'] = user.phoneNum
        user_data['dateOfBirth'] = user.dateOfBirth
        # user_data['image_id'] = user.image_id
        user_data['password'] = user.password

        result.append(user_data)

    return jsonify({'users': result})


        #--------------------------------APPEARANCE INFO--------------------------------

@views.route('/addMyApperanceInfo', methods=['GET', 'POST'])
@token_required
def addMyApperanceInfo(current_user):
        if request.method == 'POST':
            data = request.get_json()
            height=data['height']
            weight=data['weight']
            skintone=data['skintone']
            shoe_size = data['shoe_size']
            shirt_size = data['shirt_size']
            pant_size = data['pant_size']
            skirt_size = data['skirt_size']
            dress_size = data['dress_size']

            newApperanceInfo = apperanceInfo(height=height,weight=weight,skintone=skintone,shoe_size=shoe_size,shirt_size=shirt_size,pant_size=pant_size,skirt_size=skirt_size,dress_size=dress_size,users_id=current_user.id )
            db.session.add(newApperanceInfo)
            db.session.commit()
            return jsonify({'message': 'new ApperanceInfo is added successfully'})

@views.route('/getMyApperanceInfo', methods=['POST', 'GET'])
@token_required
def getMyApperanceInfo(current_user):
            apperanceinfo = apperanceInfo.query.filter_by(users_id=current_user.id).first()
            if not apperanceinfo:
                return jsonify({'message': 'There is no apperanceInfo yet .. Try to typ something!'})

            apperanceinfo_data = {}
            apperanceinfo_data['height'] = apperanceinfo.height
            apperanceinfo_data['weight'] = apperanceinfo.weight
            apperanceinfo_data['skintone'] = apperanceinfo.skintone
            apperanceinfo_data['shoe_size'] = apperanceinfo.shoe_size
            apperanceinfo_data['shirt_size'] = apperanceinfo.shirt_size
            apperanceinfo_data['pant_size'] = apperanceinfo.pant_size
            apperanceinfo_data['skirt_size'] = apperanceinfo.skirt_size
            apperanceinfo_data['dress_size'] = apperanceinfo.dress_size


            return jsonify({'the list of my apperanceInfo': apperanceinfo_data})



        #---------------------------INTERESTS ---------------------------

@views.route('/addCategory', methods=['GET', 'POST'])
@token_required
def addCategory(current_user):
        if request.method == 'POST':
            imageType = "Category_pic"
            image_id = upload(current_user, request, imageType)
            data = request.form
            item = data['item']
            newCategory = fullInterests(item=item,image_id=image_id)
            db.session.add(newCategory)
            db.session.commit()
            return jsonify({'message': 'new category in interests is added successfully'})



@views.route('/getCategories', methods=['POST', 'GET'])
@token_required
def getCategories(current_user):
            categories = fullInterests.query.all()
            if not categories:
                return jsonify({'message': 'There is no interests yet .. Try to add something!'})
            output = []
            for category in categories:
                categories_data = {}
                categories_data['category_id'] = category.id
                categories_data['item'] = category.item
                output.append(categories_data)
            return jsonify({'the list of interests': output})


@views.route('/chooseInterests',methods=['POST', 'GET'])
@token_required
def chooseInterests(current_user):
    if request.method == 'POST':
        data= request.get_json()

        if data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data["id7"] and data["id8"] and data["id9"] and data["id10"] and data["id11"] and data["id12"] and data["id13"] :
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            id6 = data["id6"]
            id7 = data["id7"]
            id8 = data["id8"]
            id9 = data["id9"]
            id10 = data["id10"]
            id11 = data["id11"]
            id12 = data["id12"]
            id13 = data["id13"]


            interest1 = fullInterests.query.filter_by(id=id1).first()
            interest2 = fullInterests.query.filter_by(id=id2).first()
            interest3 = fullInterests.query.filter_by(id=id3).first()
            interest4 = fullInterests.query.filter_by(id=id4).first()
            interest5 = fullInterests.query.filter_by(id=id5).first()
            interest6 = fullInterests.query.filter_by(id=id6).first()
            interest7 = fullInterests.query.filter_by(id=id7).first()
            interest8 = fullInterests.query.filter_by(id=id8).first()
            interest9 = fullInterests.query.filter_by(id=id9).first()
            interest10 = fullInterests.query.filter_by(id=id10).first()
            interest11 = fullInterests.query.filter_by(id=id11).first()
            interest12 = fullInterests.query.filter_by(id=id12).first()
            interest13 = fullInterests.query.filter_by(id=id13).first()


            userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                          item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id,
                                          item6_id=interest6.id, item7_id=interest7.id, item8_id=interest8.id,
                                          item9_id=interest9.id,item10_id=interest10.id,item11_id=interest11.id,item12_id=interest12.id,item13_id=interest13.id)
            db.session.add(userinterests)
            db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data[
            "id7"] and data["id8"] and data["id9"] and data["id10"] and data["id11"] and data["id12"] :
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            id6 = data["id6"]
            id7 = data["id7"]
            id8 = data["id8"]
            id9 = data["id9"]
            id10 = data["id10"]
            id11 = data["id11"]
            id12 = data["id12"]

            interest1 = fullInterests.query.filter_by(id=id1).first()
            interest2 = fullInterests.query.filter_by(id=id2).first()
            interest3 = fullInterests.query.filter_by(id=id3).first()
            interest4 = fullInterests.query.filter_by(id=id4).first()
            interest5 = fullInterests.query.filter_by(id=id5).first()
            interest6 = fullInterests.query.filter_by(id=id6).first()
            interest7 = fullInterests.query.filter_by(id=id7).first()
            interest8 = fullInterests.query.filter_by(id=id8).first()
            interest9 = fullInterests.query.filter_by(id=id9).first()
            interest10 = fullInterests.query.filter_by(id=id10).first()
            interest11 = fullInterests.query.filter_by(id=id11).first()
            interest12 = fullInterests.query.filter_by(id=id12).first()

            userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id,item6_id=interest6.id, item7_id=interest7.id, item8_id=interest8.id,item9_id=interest9.id,item10_id=interest10.id,item11_id=interest11.id,item12_id=interest12.id)
            db.session.add(userinterests)
            db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data[
            "id7"] and data["id8"] and data["id9"] and data["id10"] and data["id11"] :
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            id6 = data["id6"]
            id7 = data["id7"]
            id8 = data["id8"]
            id9 = data["id9"]
            id10 = data["id10"]
            id11 = data["id11"]

            interest1 = fullInterests.query.filter_by(id=id1).first()
            interest2 = fullInterests.query.filter_by(id=id2).first()
            interest3 = fullInterests.query.filter_by(id=id3).first()
            interest4 = fullInterests.query.filter_by(id=id4).first()
            interest5 = fullInterests.query.filter_by(id=id5).first()
            interest6 = fullInterests.query.filter_by(id=id6).first()
            interest7 = fullInterests.query.filter_by(id=id7).first()
            interest8 = fullInterests.query.filter_by(id=id8).first()
            interest9 = fullInterests.query.filter_by(id=id9).first()
            interest10 = fullInterests.query.filter_by(id=id10).first()
            interest11 = fullInterests.query.filter_by(id=id11).first()

            userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                          item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id,
                                          item6_id=interest6.id, item7_id=interest7.id, item8_id=interest8.id,
                                          item9_id=interest9.id,
                                          item10_id=interest10.id,
                                          item11_id=interest11.id)
            db.session.add(userinterests)
            db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data[
            "id7"] and data["id8"] and data["id9"] and data["id10"] :
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            id6 = data["id6"]
            id7 = data["id7"]
            id8 = data["id8"]
            id9 = data["id9"]
            id10 = data["id10"]

            interest1 = fullInterests.query.filter_by(id=id1).first()
            interest2 = fullInterests.query.filter_by(id=id2).first()
            interest3 = fullInterests.query.filter_by(id=id3).first()
            interest4 = fullInterests.query.filter_by(id=id4).first()
            interest5 = fullInterests.query.filter_by(id=id5).first()
            interest6 = fullInterests.query.filter_by(id=id6).first()
            interest7 = fullInterests.query.filter_by(id=id7).first()
            interest8 = fullInterests.query.filter_by(id=id8).first()
            interest9 = fullInterests.query.filter_by(id=id9).first()
            interest10 = fullInterests.query.filter_by(id=id10).first()

            userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                          item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id,
                                          item6_id=interest6.id, item7_id=interest7.id, item8_id=interest8.id,
                                          item9_id=interest9.id,
                                          item10_id=interest10.id)
            db.session.add(userinterests)
            db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and  data["id6"]and data["id7"] and data["id8"] and data["id9"]  :
           id1 = data["id1"]
           id2 = data["id2"]
           id3 = data["id3"]
           id4 = data["id4"]
           id5 = data["id5"]
           id6 = data["id6"]
           id7 = data["id7"]
           id8 = data["id8"]
           id9 = data["id9"]

           interest1 = fullInterests.query.filter_by(id=id1).first()
           interest2 = fullInterests.query.filter_by(id=id2).first()
           interest3 = fullInterests.query.filter_by(id=id3).first()
           interest4 = fullInterests.query.filter_by(id=id4).first()
           interest5 = fullInterests.query.filter_by(id=id5).first()
           interest6 = fullInterests.query.filter_by(id=id6).first()
           interest7 = fullInterests.query.filter_by(id=id7).first()
           interest8 = fullInterests.query.filter_by(id=id8).first()
           interest9 = fullInterests.query.filter_by(id=id9).first()

           userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                         item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id,
                                         item6_id=interest6.id, item7_id=interest7.id, item8_id=interest8.id,item9_id=interest9.id )
           db.session.add(userinterests)
           db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and  data["id6"]and data["id7"] and data["id8"] :
           id1 = data["id1"]
           id2 = data["id2"]
           id3 = data["id3"]
           id4 = data["id4"]
           id5 = data["id5"]
           id6 = data["id6"]
           id7 = data["id7"]
           id8 = data["id8"]

           interest1 = fullInterests.query.filter_by(id=id1).first()
           interest2 = fullInterests.query.filter_by(id=id2).first()
           interest3 = fullInterests.query.filter_by(id=id3).first()
           interest4 = fullInterests.query.filter_by(id=id4).first()
           interest5 = fullInterests.query.filter_by(id=id5).first()
           interest6 = fullInterests.query.filter_by(id=id6).first()
           interest7 = fullInterests.query.filter_by(id=id7).first()
           interest8 = fullInterests.query.filter_by(id=id8).first()
           userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                         item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id,
                                         item6_id=interest6.id, item7_id=interest7.id, item8_id=interest8.id)
           db.session.add(userinterests)
           db.session.commit()


        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data["id7"] :
           id1 = data["id1"]
           id2 = data["id2"]
           id3 = data["id3"]
           id4 = data["id4"]
           id5 = data["id5"]
           id6 = data["id6"]
           id7 = data["id7"]
           interest1 = fullInterests.query.filter_by(id=id1).first()
           interest2 = fullInterests.query.filter_by(id=id2).first()
           interest3 = fullInterests.query.filter_by(id=id3).first()
           interest4 = fullInterests.query.filter_by(id=id4).first()
           interest5 = fullInterests.query.filter_by(id=id5).first()
           interest6 = fullInterests.query.filter_by(id=id6).first()
           interest7 = fullInterests.query.filter_by(id=id7).first()
           userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                         item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id,
                                         item6_id=interest6.id, item7_id=interest7.id)
           db.session.add(userinterests)
           db.session.commit()


        elif data["id1"] and data["id2"] and data["id3"] and  data["id4"] and data["id5"] and data["id6"]:
           id1 = data["id1"]
           id2 = data["id2"]
           id3 = data["id3"]
           id4 = data["id4"]
           id5 = data["id5"]
           id6 = data["id6"]
           interest1 = fullInterests.query.filter_by(id=id1).first()
           interest2 = fullInterests.query.filter_by(id=id2).first()
           interest3 = fullInterests.query.filter_by(id=id3).first()
           interest4 = fullInterests.query.filter_by(id=id4).first()
           interest5 = fullInterests.query.filter_by(id=id5).first()
           interest6 = fullInterests.query.filter_by(id=id6).first()
           userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                         item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id,
                                         item6_id=interest6.id)
           db.session.add(userinterests)
           db.session.commit()


        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] :
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            interest1 = fullInterests.query.filter_by(id=id1).first()
            interest2 = fullInterests.query.filter_by(id=id2).first()
            interest3 = fullInterests.query.filter_by(id=id3).first()
            interest4 = fullInterests.query.filter_by(id=id4).first()
            interest5 = fullInterests.query.filter_by(id=id5).first()
            userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                         item3_id=interest3.id, item4_id=interest4.id, item5_id=interest5.id)
            db.session.add(userinterests)
            db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] :
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            interest1 = fullInterests.query.filter_by(id=id1).first()
            interest2 = fullInterests.query.filter_by(id=id2).first()
            interest3 = fullInterests.query.filter_by(id=id3).first()
            interest4 = fullInterests.query.filter_by(id=id4).first()
            userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                         item3_id=interest3.id, item4_id=interest4.id)
            db.session.add(userinterests)
            db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"] :
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            interest1 = fullInterests.query.filter_by(id=id1).first()
            interest2 = fullInterests.query.filter_by(id=id2).first()
            interest3 = fullInterests.query.filter_by(id=id3).first()
            userinterests = userInterests(users_id=current_user.id, item1_id=interest1.id, item2_id=interest2.id,
                                        item3_id=interest3.id)
            db.session.add(userinterests)
            db.session.commit()

        return jsonify({'message': 'your items are chosen successfully'})


@views.route('/getMyInterests', methods=['POST', 'GET'])
@token_required
def getMyInterests(current_user):
            userinterests = userInterests.query.filter_by(users_id=current_user.id).first()

            if not userinterests:
                return jsonify({'message': 'you do not choose your interests yet .. Try to choose something!'})

            userInterests_data = {}
            userInterests_data['item1'] = userinterests.item1_id
            userInterests_data['item2'] = userinterests.item2_id
            userInterests_data['item3'] = userinterests.item3_id
            userInterests_data['item4'] = userinterests.item4_id
            userInterests_data['item5'] = userinterests.item5_id
            userInterests_data['item6'] = userinterests.item6_id
            userInterests_data['item7'] = userinterests.item7_id
            userInterests_data['item8'] = userinterests.item8_id
            userInterests_data['item9'] = userinterests.item9_id
            userInterests_data['item10'] = userinterests.item10_id
            userInterests_data['item11'] = userinterests.item11_id
            userInterests_data['item12'] = userinterests.item12_id
            userInterests_data['item13'] = userinterests.item13_id


            return jsonify({'the list of my chosen interests': userInterests_data})

@views.route('/unfavorite_item/<item_id>', methods=['PUT','GET'])
@token_required
def unfavoriteItem(current_user, item_id):
        interest = userInterests.query.filter_by(users_id=current_user.id).first()

        if not interest:
            return jsonify({'message': 'there is no exist for this item'})

        if  str(item_id) == str(interest.item1_id):
            interest.item1_id=''
            db.session.commit()

        if str(item_id) == str(interest.item2_id):
            interest.item2_id=""
            db.session.commit()

        if str(item_id) == str(interest.item3_id):
            interest.item3_id=''
            db.session.commit()

        if str(item_id) == str(interest.item4_id):
            interest.item4_id=''
            db.session.commit()

        if str(item_id) == str(interest.item5_id) :
            interest.item5_id=''
            db.session.commit()

        if str(item_id) == str(interest.item6_id) :
            interest.item6_id=''
            db.session.commit()

        if str(item_id) == str(interest.item7_id) :
            interest.item7_id=''
            db.session.commit()

        if str(item_id) == str(interest.item8_id) :
            interest.item8_id=''
            db.session.commit()

        if str(item_id) == str(interest.item9_id) :
            interest.item9_id=''
            db.session.commit()

        if str(item_id) == str(interest.item10_id) :
            interest.item10_id=''
            db.session.commit()

        if str(item_id) == str(interest.item11_id) :
            interest.item11_id=''
            db.session.commit()

        if str(item_id) == str(interest.item12_id) :
            interest.item12_id=''
            db.session.commit()

        if str(item_id) == str(interest.item13_id):
            interest.item13_id=''
            db.session.commit()

        return jsonify({'message': 'item is unfavorite'})

       #---------------------------EVENTS ---------------------------

@views.route('/addEvent', methods=['GET', 'POST'])
@token_required
def addEvent(current_user):
        if request.method == 'POST':
            imageType = "Event_pic"
            image_id = upload(current_user, request, imageType)
            data = request.form
            item = data['item']

            newEvent = fullEvents(item=item,image_id=image_id)
            db.session.add(newEvent)
            db.session.commit()
            return jsonify({'message': 'new event is added successfully'})



@views.route('/getEvents', methods=['POST', 'GET'])
@token_required
def getEvents(current_user):
            events = fullEvents.query.all()
            if not events:
                return jsonify({'message': 'There is no events yet .. Try to add something!'})
            output = []
            for event in events:
                events_data = {}
                events_data['event_id'] = event.id
                events_data['item'] = event.item
                output.append(events_data)
            return jsonify({'the list of events': output})


@views.route('/chooseEvents',methods=['POST', 'GET'])
@token_required
def chooseEvents(current_user):
    if request.method == 'POST':

      data = request.get_json()

      if data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data[
            "id7"] and data["id8"]:
        id1 = data["id1"]
        id2 = data["id2"]
        id3 = data["id3"]
        id4 = data["id4"]
        id5 = data["id5"]
        id6 = data["id6"]
        id7 = data["id7"]
        id8 = data["id8"]

        event1 = fullEvents.query.filter_by(id=id1).first()
        event2 = fullEvents.query.filter_by(id=id2).first()
        event3 = fullEvents.query.filter_by(id=id3).first()
        event4 = fullEvents.query.filter_by(id=id4).first()
        event5 = fullEvents.query.filter_by(id=id5).first()
        event6 = fullEvents.query.filter_by(id=id6).first()
        event7 = fullEvents.query.filter_by(id=id7).first()
        event8 = fullEvents.query.filter_by(id=id8).first()
        userevents = userEvents(users_id=current_user.id, item1_id=event1.id, item2_id=event2.id,
                                      item3_id=event3.id, item4_id=event4.id, item5_id=event5.id,
                                      item6_id=event6.id, item7_id=event7.id, item8_id=event8.id)
        db.session.add(userevents)
        db.session.commit()


      elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data["id7"]:
        id1 = data["id1"]
        id2 = data["id2"]
        id3 = data["id3"]
        id4 = data["id4"]
        id5 = data["id5"]
        id6 = data["id6"]
        id7 = data["id7"]
        event1 = fullEvents.query.filter_by(id=id1).first()
        event2 = fullEvents.query.filter_by(id=id2).first()
        event3 = fullEvents.query.filter_by(id=id3).first()
        event4 = fullEvents.query.filter_by(id=id4).first()
        event5 = fullEvents.query.filter_by(id=id5).first()
        event6 = fullEvents.query.filter_by(id=id6).first()
        event7 = fullEvents.query.filter_by(id=id7).first()
        userevents = userEvents(users_id=current_user.id, item1_id=event1.id, item2_id=event2.id,
                                item3_id=event3.id, item4_id=event4.id, item5_id=event5.id,
                                item6_id=event6.id, item7_id=event7.id)
        db.session.add(userevents)
        db.session.commit()


      elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"]:
         id1 = data["id1"]
         id2 = data["id2"]
         id3 = data["id3"]
         id4 = data["id4"]
         id5 = data["id5"]
         id6 = data["id6"]
         event1 = fullEvents.query.filter_by(id=id1).first()
         event2 = fullEvents.query.filter_by(id=id2).first()
         event3 = fullEvents.query.filter_by(id=id3).first()
         event4 = fullEvents.query.filter_by(id=id4).first()
         event5 = fullEvents.query.filter_by(id=id5).first()
         event6 = fullEvents.query.filter_by(id=id6).first()
         userevents = userEvents(users_id=current_user.id, item1_id=event1.id, item2_id=event2.id,
                                 item3_id=event3.id, item4_id=event4.id, item5_id=event5.id,
                                 item6_id=event6.id)
         db.session.add(userevents)
         db.session.commit()


      elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"]:
          id1 = data["id1"]
          id2 = data["id2"]
          id3 = data["id3"]
          id4 = data["id4"]
          id5 = data["id5"]
          event1 = fullEvents.query.filter_by(id=id1).first()
          event2 = fullEvents.query.filter_by(id=id2).first()
          event3 = fullEvents.query.filter_by(id=id3).first()
          event4 = fullEvents.query.filter_by(id=id4).first()
          event5 = fullEvents.query.filter_by(id=id5).first()
          userevents = userEvents(users_id=current_user.id, item1_id=event1.id, item2_id=event2.id,
                                  item3_id=event3.id, item4_id=event4.id, item5_id=event5.id)
          db.session.add(userevents)
          db.session.commit()

      elif data["id1"] and data["id2"] and data["id3"] and data["id4"]:
          id1 = data["id1"]
          id2 = data["id2"]
          id3 = data["id3"]
          id4 = data["id4"]
          event1 = fullEvents.query.filter_by(id=id1).first()
          event2 = fullEvents.query.filter_by(id=id2).first()
          event3 = fullEvents.query.filter_by(id=id3).first()
          event4 = fullEvents.query.filter_by(id=id4).first()
          userevents = userEvents(users_id=current_user.id, item1_id=event1.id, item2_id=event2.id,
                                  item3_id=event3.id, item4_id=event4.id)
          db.session.add(userevents)
          db.session.commit()

      elif data["id1"] and data["id2"] and data["id3"]:
          id1 = data["id1"]
          id2 = data["id2"]
          id3 = data["id3"]
          event1 = fullEvents.query.filter_by(id=id1).first()
          event2 = fullEvents.query.filter_by(id=id2).first()
          event3 = fullEvents.query.filter_by(id=id3).first()
          userevents = userEvents(users_id=current_user.id, item1_id=event1.id, item2_id=event2.id,
                                  item3_id=event3.id)
          db.session.add(userevents)
          db.session.commit()

    return jsonify({'message': 'your Events are chosen successfully'})

@views.route('/getMyEvents', methods=['POST', 'GET'])
@token_required
def getMyEvents(current_user):
            userevents = userEvents.query.filter_by(users_id=current_user.id).first()

            if not userevents:
                return jsonify({'message': 'you do not choose your events yet .. Try to choose something!'})

            userEvents_data = {}
            userEvents_data['item1'] = userevents.item1_id
            userEvents_data['item2'] = userevents.item2_id
            userEvents_data['item3'] = userevents.item3_id
            userEvents_data['item4'] = userevents.item4_id
            userEvents_data['item5'] = userevents.item5_id
            userEvents_data['item6'] = userevents.item6_id
            userEvents_data['item7'] = userevents.item7_id
            userEvents_data['item8'] = userevents.item8_id
            return jsonify({'the list of my chosen events': userEvents_data})

@views.route('/unfavorite_event/<item_id>', methods=['PUT','GET'])
@token_required
def unfavoriteEvent(current_user, item_id):
        event = userEvents.query.filter_by(users_id=current_user.id).first()

        if not event:
            return jsonify({'message': 'there is no exist for this Event'})

        if  str(item_id) == str(event.item1_id):
            event.item1_id=''
            db.session.commit()

        if str(item_id) == str(event.item2_id):
            event.item2_id=""
            db.session.commit()

        if str(item_id) == str(event.item3_id):
            event.item3_id=''
            db.session.commit()

        if str(item_id) == str(event.item4_id):
            event.item4_id=''
            db.session.commit()

        if str(item_id) == str(event.item5_id) :
            event.item5_id=''
            db.session.commit()

        if str(item_id) == str(event.item6_id) :
            event.item6_id=''
            db.session.commit()

        if str(item_id) == str(event.item7_id) :
            event.item7_id=''
            db.session.commit()

        if str(item_id) == str(event.item8_id) :
            event.item8_id=''
            db.session.commit()

        return jsonify({'message': 'Event is unfavorite'})

           #---------------------------AESTHETIC ---------------------------

@views.route('/addAesthetic', methods=['GET', 'POST'])
@token_required
def addAesthetic(current_user):
        if request.method == 'POST':
            imageType = "Aesthetic_pic"
            image_id = upload(current_user, request, imageType)
            data = request.form
            item = data['item']

            newAesthetic = fullAesthetics(item=item,image_id=image_id)
            db.session.add(newAesthetic)
            db.session.commit()
            return jsonify({'message': 'new Aesthetic is added successfully'})



@views.route('/getAesthetics', methods=['POST', 'GET'])
@token_required
def getAesthetics(current_user):
            aesthetics = fullAesthetics.query.all()
            if not aesthetics:
                return jsonify({'message': 'There is no aesthetics yet .. Try to add something!'})
            output = []
            for aesthetic in aesthetics:
                aesthetics_data = {}
                aesthetics_data['aesthetic_id'] = aesthetic.id
                aesthetics_data['item'] = aesthetic.item
                output.append(aesthetics_data)
            return jsonify({'the list of aesthetics': output})


@views.route('/chooseAesthetics',methods=['POST', 'GET'])
@token_required
def chooseAesthetics(current_user):
    if request.method == 'POST':

        data = request.get_json()

        if data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data[
            "id7"] and data["id8"]:
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            id6 = data["id6"]
            id7 = data["id7"]
            id8 = data["id8"]

            aesthetic1 = fullAesthetics.query.filter_by(id=id1).first()
            aesthetic2 = fullAesthetics.query.filter_by(id=id2).first()
            aesthetic3 = fullAesthetics.query.filter_by(id=id3).first()
            aesthetic4 = fullAesthetics.query.filter_by(id=id4).first()
            aesthetic5 = fullAesthetics.query.filter_by(id=id5).first()
            aesthetic6 = fullAesthetics.query.filter_by(id=id6).first()
            aesthetic7 = fullAesthetics.query.filter_by(id=id7).first()
            aesthetic8 = fullAesthetics.query.filter_by(id=id8).first()
            useraesthetics = userAesthetics(users_id=current_user.id, item1_id=aesthetic1.id, item2_id=aesthetic2.id,
                                    item3_id=aesthetic3.id, item4_id=aesthetic4.id, item5_id=aesthetic5.id,
                                    item6_id=aesthetic6.id, item7_id=aesthetic7.id, item8_id=aesthetic8.id)
            db.session.add(useraesthetics)
            db.session.commit()


        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"] and data[
            "id7"]:
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            id6 = data["id6"]
            id7 = data["id7"]

            aesthetic1 = fullAesthetics.query.filter_by(id=id1).first()
            aesthetic2 = fullAesthetics.query.filter_by(id=id2).first()
            aesthetic3 = fullAesthetics.query.filter_by(id=id3).first()
            aesthetic4 = fullAesthetics.query.filter_by(id=id4).first()
            aesthetic5 = fullAesthetics.query.filter_by(id=id5).first()
            aesthetic6 = fullAesthetics.query.filter_by(id=id6).first()
            aesthetic7 = fullAesthetics.query.filter_by(id=id7).first()

            useraesthetics = userAesthetics(users_id=current_user.id, item1_id=aesthetic1.id, item2_id=aesthetic2.id,
                                            item3_id=aesthetic3.id, item4_id=aesthetic4.id, item5_id=aesthetic5.id,
                                            item6_id=aesthetic6.id, item7_id=aesthetic7.id)
            db.session.add(useraesthetics)
            db.session.commit()


        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"] and data["id6"]:
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            id6 = data["id6"]
            aesthetic1 = fullAesthetics.query.filter_by(id=id1).first()
            aesthetic2 = fullAesthetics.query.filter_by(id=id2).first()
            aesthetic3 = fullAesthetics.query.filter_by(id=id3).first()
            aesthetic4 = fullAesthetics.query.filter_by(id=id4).first()
            aesthetic5 = fullAesthetics.query.filter_by(id=id5).first()
            aesthetic6 = fullAesthetics.query.filter_by(id=id6).first()

            useraesthetics = userAesthetics(users_id=current_user.id, item1_id=aesthetic1.id, item2_id=aesthetic2.id,
                                            item3_id=aesthetic3.id, item4_id=aesthetic4.id, item5_id=aesthetic5.id,
                                            item6_id=aesthetic6.id)
            db.session.add(useraesthetics)
            db.session.commit()


        elif data["id1"] and data["id2"] and data["id3"] and data["id4"] and data["id5"]:
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            id5 = data["id5"]
            aesthetic1 = fullAesthetics.query.filter_by(id=id1).first()
            aesthetic2 = fullAesthetics.query.filter_by(id=id2).first()
            aesthetic3 = fullAesthetics.query.filter_by(id=id3).first()
            aesthetic4 = fullAesthetics.query.filter_by(id=id4).first()
            aesthetic5 = fullAesthetics.query.filter_by(id=id5).first()

            useraesthetics = userAesthetics(users_id=current_user.id, item1_id=aesthetic1.id, item2_id=aesthetic2.id,
                                            item3_id=aesthetic3.id, item4_id=aesthetic4.id, item5_id=aesthetic5.id)
            db.session.add(useraesthetics)
            db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"] and data["id4"]:
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            id4 = data["id4"]
            aesthetic1 = fullAesthetics.query.filter_by(id=id1).first()
            aesthetic2 = fullAesthetics.query.filter_by(id=id2).first()
            aesthetic3 = fullAesthetics.query.filter_by(id=id3).first()
            aesthetic4 = fullAesthetics.query.filter_by(id=id4).first()

            useraesthetics = userAesthetics(users_id=current_user.id, item1_id=aesthetic1.id, item2_id=aesthetic2.id,
                                            item3_id=aesthetic3.id, item4_id=aesthetic4.id)
            db.session.add(useraesthetics)
            db.session.commit()

        elif data["id1"] and data["id2"] and data["id3"]:
            id1 = data["id1"]
            id2 = data["id2"]
            id3 = data["id3"]
            aesthetic1 = fullAesthetics.query.filter_by(id=id1).first()
            aesthetic2 = fullAesthetics.query.filter_by(id=id2).first()
            aesthetic3 = fullAesthetics.query.filter_by(id=id3).first()

            useraesthetics = userAesthetics(users_id=current_user.id, item1_id=aesthetic1.id, item2_id=aesthetic2.id,
                                            item3_id=aesthetic3.id)
            db.session.add(useraesthetics)
            db.session.commit()

    return jsonify({'message': 'your Aesthetics are chosen successfully'})

@views.route('/getMyAesthetics', methods=['POST', 'GET'])
@token_required
def getMyAesthetics(current_user):
            useraesthetics = userAesthetics.query.filter_by(users_id=current_user.id).first()

            if not useraesthetics:
                return jsonify({'message': 'you do not choose your Aesthetics yet .. Try to choose something!'})

            userAesthetics_data = {}
            userAesthetics_data['item1'] = useraesthetics.item1_id
            userAesthetics_data['item2'] = useraesthetics.item2_id
            userAesthetics_data['item3'] = useraesthetics.item3_id
            userAesthetics_data['item4'] = useraesthetics.item4_id
            userAesthetics_data['item5'] = useraesthetics.item5_id
            userAesthetics_data['item6'] = useraesthetics.item6_id
            userAesthetics_data['item7'] = useraesthetics.item7_id
            userAesthetics_data['item8'] = useraesthetics.item8_id
            return jsonify({'the list of my chosen Aesthetics': userAesthetics_data})

@views.route('/unfavorite_Aesthetic/<item_id>', methods=['PUT','GET'])
@token_required
def unfavoriteAesthetic(current_user, item_id):
        aesthetic = userAesthetics.query.filter_by(users_id=current_user.id).first()

        if not aesthetic:
            return jsonify({'message': 'there is no exist for this Aesthetic'})

        if  str(item_id) == str(aesthetic.item1_id):
            aesthetic.item1_id=''
            db.session.commit()

        if str(item_id) == str(aesthetic.item2_id):
            aesthetic.item2_id=""
            db.session.commit()

        if str(item_id) == str(aesthetic.item3_id):
            aesthetic.item3_id=''
            db.session.commit()

        if str(item_id) == str(aesthetic.item4_id):
            aesthetic.item4_id=''
            db.session.commit()

        if str(item_id) == str(aesthetic.item5_id) :
            aesthetic.item5_id=''
            db.session.commit()

        if str(item_id) == str(aesthetic.item6_id) :
            aesthetic.item6_id=''
            db.session.commit()

        if str(item_id) == str(aesthetic.item7_id) :
            aesthetic.item7_id=''
            db.session.commit()

        if str(item_id) == str(aesthetic.item8_id) :
            aesthetic.item8_id=''
            db.session.commit()

        return jsonify({'message': 'Aesthetic is unfavorite'})


#--------------------------------Profile--------------------------------

@views.route('/addProfileInfo', methods=[ 'GET','POST','PUT'])
@token_required
def addProfileInfo(current_user):

            user=Users.query.filter_by(id=current_user.id).first()
            user_profile=Profile.query.filter_by(user_id=user.id).first()
            if  user_profile:
                    imageType = "Profile_pic"
                    image_id = upload(current_user, request, imageType)
                    data = request.form
                    bio = data['bio']
                    fb_link = data['fb_link']
                    ig_link = data['ig_link']
                    pinterest_link = data['pinterest_link']
                    userprofile = Profile.query.filter_by(user_id=user.id).update(
                        dict(bio=bio, fb_link=fb_link, ig_link=ig_link, pinterest_link=pinterest_link, image_id=image_id))
                    db.session.commit()
                    return jsonify({'message': ' ProfileInfo is updated successfully'})

            elif not user_profile:
                    imageType = "Profile_pic"
                    image_id = upload(current_user, request, imageType)
                    data = request.form
                    bio = data['bio']
                    fb_link = data['fb_link']
                    ig_link = data['ig_link']
                    pinterest_link = data['pinterest_link']

                    newProfileInfo = Profile(bio=bio,fb_link=fb_link,ig_link=ig_link,pinterest_link=pinterest_link,user_id=current_user.id,image_id=image_id)
                    db.session.add(newProfileInfo)
                    db.session.commit()
                    return jsonify({'message': 'new ProfileInfo is added successfully'})
            else:
                    return jsonify({'message': 'please enter your profile info'})


@views.route('/profile_Page/profile_Info', methods=['POST', 'GET'])
@token_required
def getProfileInfo(current_user):
            user = Users.query.filter_by(id=current_user.id).first()
            profile=Profile.query.filter_by(user_id=user.id).first()
            if profile:
                im = Img.query.filter_by(id=profile.image_id).first()
            bioAndlinks=Profile.query.filter_by(user_id=user.id).first()
            postCount = Posts.query.filter_by(user_id=user.id).count()
            followingCount = Followers.query.filter_by(follower_id=user.id).count()
            followersCount = Followers.query.filter_by(followed_id=user.id).count()
            user_data = {}
            user_data['user_id'] = user.id
            if profile:
                user_data['image_url'] =im.img
            user_data['username'] = user.username
            if not bioAndlinks:
                user_data['bio'] = "you can add your bio"
            else:
                user_data['bio'] = bioAndlinks.bio
                user_data['fb_link'] = bioAndlinks.fb_link
                user_data['ig_link'] = bioAndlinks.ig_link
                user_data['pinterest_link'] = bioAndlinks.pinterest_link
            user_data['following Num'] = followingCount
            user_data['followers Num'] = followersCount
            user_data['num of posts'] = postCount
            # user_data['profilePosts_link'] = "http://127.0.0.1:5001/profile_Page/profile_Posts"
            # user_data['profileFavorites_link'] = "http://127.0.0.1:5001/profile_Page/profile_Favorites"
            # user_data['profileCategories_link'] = "http://127.0.0.1:5001/profile_Page/profile_Categories"


            return jsonify({'My Profile Info': user_data})

@views.route('/profile_Page/profile_Posts', methods=['POST', 'GET'])
@token_required
def getProfilePosts(current_user):
    user = Users.query.filter_by(id=current_user.id).first()
    profile = Profile.query.filter_by(user_id=user.id).first()
    if profile:
        im = Img.query.filter_by(id=profile.image_id).first()

    posts = Posts.query.filter_by(user_id=current_user.id).all()
    if not posts:
        post_data = {}
        post_data['message'] = 'there is no posts of you yet,, Try to post something '

    post_output = []
    for post in posts:
        imgg = Img.query.filter_by(id=post.image_id).first()
        numOfLikes = PostLike.query.filter_by(post_id=post.id).count()
        numOfComments = PostComment.query.filter_by(post_id=post.id).count()
        numOfSharing = SharePost.query.filter_by(post_id=post.id).count()

        post_data = {}
        post_data['by'] = user.username
        if profile:
             post_data['user profile pic'] = im.img
        post_data['timePosted'] = post.date
        post_data['location'] = post.location
        post_data['image_url'] = imgg.img
        post_data['desc'] = post.desc
        post_data['num of likes'] = numOfLikes
        post_data['num of Comments'] = numOfComments
        post_data['num of Sharing'] = numOfSharing
        post_data['post_id'] = post.id
        post_output.append(post_data)
    return jsonify({'My Posts': post_output})

@views.route('/profile_Page/profile_Favorites', methods=['POST', 'GET'])
@token_required
def getProfileFavorites(current_user):
        user = Users.query.filter_by(id=current_user.id).first()
        likes = PostLike.query.filter_by(users_id=user.id).all()
        if not likes:
            return jsonify({'messgae': 'there is no posts u like yet'})
        else :
            post_output = []
            for like in likes:
               post = Posts.query.filter_by(id=like.post_id).first()
               userr=Users.query.filter_by(id=post.user_id).first()
               profile = Profile.query.filter_by(user_id=userr.id).first()
               if profile:
                   im = Img.query.filter_by(id=profile.image_id).first()
               imgg = Img.query.filter_by(id=post.image_id).first()
               numOfLikes = PostLike.query.filter_by(post_id=post.id).count()
               numOfComments = PostComment.query.filter_by(post_id=post.id).count()
               numOfSharing = SharePost.query.filter_by(post_id=post.id).count()
               post_data = {}
               post_data['by'] = userr.username
               if profile:
                  post_data['user profile pic'] = im.img
               post_data['timePosted'] = post.date
               post_data['location'] = post.location
               post_data['image_url'] = imgg.img
               post_data['desc'] = post.desc
               post_data['num of likes'] = numOfLikes
               post_data['num of Comments'] = numOfComments
               post_data['num of Sharing'] = numOfSharing
               post_data['post_id'] = post.id
               post_output.append(post_data)
            return jsonify({'My Favorites': post_output})

@views.route('/profile_Page/profile_Categories', methods=['POST', 'GET'])
@token_required
def getProfileCategories(current_user):
            user = Users.query.filter_by(id=current_user.id).first()
            interests = userInterests.query.filter_by(users_id=user.id).first()
            if not interests:
                interests_data = {}
                interests_data['message_items'] = "there is no items yet, try to add your favourite items!"


            else :
                interest1_data=fullInterests.query.filter_by(id=interests.item1_id).first()
                interest2_data=fullInterests.query.filter_by(id=interests.item2_id).first()
                interest3_data=fullInterests.query.filter_by(id=interests.item3_id).first()
                interest4_data=fullInterests.query.filter_by(id=interests.item4_id).first()
                interest5_data=fullInterests.query.filter_by(id=interests.item5_id).first()
                interest6_data=fullInterests.query.filter_by(id=interests.item6_id).first()
                interest7_data=fullInterests.query.filter_by(id=interests.item7_id).first()
                interest8_data=fullInterests.query.filter_by(id=interests.item8_id).first()
                interest9_data=fullInterests.query.filter_by(id=interests.item9_id).first()
                interest10_data=fullInterests.query.filter_by(id=interests.item10_id).first()
                interest11_data=fullInterests.query.filter_by(id=interests.item11_id).first()
                interest12_data=fullInterests.query.filter_by(id=interests.item12_id).first()
                interest13_data=fullInterests.query.filter_by(id=interests.item13_id).first()

                if interest1_data:
                    img1=Img.query.filter_by(id=interest1_data.image_id).first()
                if interest2_data:
                    img2=Img.query.filter_by(id=interest2_data.image_id).first()
                if interest3_data:
                    img3=Img.query.filter_by(id=interest3_data.image_id).first()
                if interest4_data:
                    img4=Img.query.filter_by(id=interest4_data.image_id).first()
                if interest5_data:
                    img5=Img.query.filter_by(id=interest5_data.image_id).first()
                if interest6_data:
                    img6=Img.query.filter_by(id=interest6_data.image_id).first()
                if interest7_data:
                    img7=Img.query.filter_by(id=interest7_data.image_id).first()
                if interest8_data:
                    img8=Img.query.filter_by(id=interest8_data.image_id).first()
                if interest9_data:
                    img9=Img.query.filter_by(id=interest9_data.image_id).first()
                if interest10_data:
                    img10=Img.query.filter_by(id=interest10_data.image_id).first()
                if interest11_data:
                    img11=Img.query.filter_by(id=interest11_data.image_id).first()
                if interest12_data:
                    img12=Img.query.filter_by(id=interest12_data.image_id).first()
                if interest13_data:
                    img13=Img.query.filter_by(id=interest13_data.image_id).first()

                output = []
                interests1_data = {}
                interests2_data = {}
                interests3_data = {}
                interests4_data = {}
                interests5_data = {}
                interests6_data = {}
                interests7_data = {}
                interests8_data = {}
                interests9_data = {}
                interests10_data = {}
                interests11_data = {}
                interests12_data = {}
                interests13_data = {}

                if interest1_data:
                    interests1_data['item_id'] = interests.item1_id
                    interests1_data['item_name'] = interest1_data.item
                    interests1_data['item_imageUrl'] = img1.img
                    output.append(interests1_data)
                if interest2_data:
                    interests2_data['item_id'] = interests.item2_id
                    interests2_data['item_name'] = interest2_data.item
                    interests2_data['item_imageUrl'] = img2.img
                    output.append(interests2_data)
                if interest3_data:
                    interests3_data['item_id'] = interests.item3_id
                    interests3_data['item_name'] = interest3_data.item
                    interests3_data['item_imageUrl'] = img3.img
                    output.append(interests3_data)
                if interest4_data:
                    interests4_data['item_id'] = interests.item4_id
                    interests4_data['item_name'] = interest4_data.item
                    interests4_data['item_imageUrl'] = img4.img
                    output.append(interests4_data)
                if interest5_data:
                    interests5_data['item_id'] = interests.item5_id
                    interests5_data['item_name'] = interest5_data.item
                    interests5_data['item_imageUrl'] = img5.img
                    output.append(interests5_data)
                if interest6_data:
                    interests6_data['item_id'] = interests.item6_id
                    interests6_data['item_name'] = interest6_data.item
                    interests6_data['item_imageUrl'] = img6.img
                    output.append(interests6_data)

                if interest7_data:
                    interests7_data['item_id'] = interests.item7_id
                    interests7_data['item_name'] = interest7_data.item
                    interests7_data['item_imageUrl'] = img7.img
                    output.append(interests7_data)
                if interest8_data:
                    interests8_data['item_id'] = interests.item8_id
                    interests8_data['item_name'] = interest8_data.item
                    interests8_data['item_imageUrl'] = img8.img
                    output.append(interests8_data)
                if interest9_data:
                    interests9_data['item_id'] = interests.item9_id
                    interests9_data['item_name'] = interest9_data.item
                    interests9_data['item_imageUrl'] = img9.img
                    output.append(interests9_data)
                if interest10_data:
                    interests10_data['item_id'] = interests.item10_id
                    interests10_data['item_name'] = interest10_data.item
                    interests10_data['item_imageUrl'] = img10.img
                    output.append(interests10_data)
                if interest11_data:
                    interests11_data['item_id'] = interests.item11_id
                    interests11_data['item_name'] = interest11_data.item
                    interests11_data['item_imageUrl'] = img11.img
                    output.append(interests11_data)
                if interest12_data:
                    interests12_data['item_id'] = interests.item12_id
                    interests12_data['item_name'] = interest12_data.item
                    interests12_data['item_imageUrl'] = img12.img
                    output.append(interests12_data)
                if interest13_data:
                    interests13_data['item_id'] = interests.item13_id
                    interests13_data['item_name'] = interest13_data.item
                    interests13_data['item_imageUrl'] = img13.img
                    output.append(interests13_data)

            events = userEvents.query.filter_by(users_id=user.id).first()
            if not events:
                    events_data = {}
                    events_data['message_events'] = "there is no events yet, try to add your favourite events"


            else:
                    event1_data = fullEvents.query.filter_by(id=events.item1_id).first()
                    event2_data = fullEvents.query.filter_by(id=events.item2_id).first()
                    event3_data = fullEvents.query.filter_by(id=events.item3_id).first()
                    event4_data = fullEvents.query.filter_by(id=events.item4_id).first()
                    event5_data = fullEvents.query.filter_by(id=events.item5_id).first()
                    event6_data = fullEvents.query.filter_by(id=events.item6_id).first()
                    event7_data = fullEvents.query.filter_by(id=events.item7_id).first()
                    event8_data = fullEvents.query.filter_by(id=events.item8_id).first()

                    if event1_data:
                        img1 = Img.query.filter_by(id=event1_data.image_id).first()
                    if event2_data:
                        img2 = Img.query.filter_by(id=event2_data.image_id).first()
                    if event3_data:
                        img3 = Img.query.filter_by(id=event3_data.image_id).first()
                    if event4_data:
                        img4 = Img.query.filter_by(id=event4_data.image_id).first()
                    if event5_data:
                        img5 = Img.query.filter_by(id=event5_data.image_id).first()
                    if event6_data:
                        img6 = Img.query.filter_by(id=event6_data.image_id).first()
                    if event7_data:
                        img7 = Img.query.filter_by(id=event7_data.image_id).first()
                    if event8_data:
                        img8 = Img.query.filter_by(id=event8_data.image_id).first()


                    output2 = []
                    events1_data = {}
                    events2_data = {}
                    events3_data = {}
                    events4_data = {}
                    events5_data = {}
                    events6_data = {}
                    events7_data = {}
                    events8_data = {}

                    if event1_data:
                        events1_data['event_id'] = events.item1_id
                        events1_data['event_name'] = event1_data.item
                        events1_data['event_imageUrl'] = img1.img
                        output2.append(events1_data)
                    if event2_data:
                        events2_data['event_id'] = events.item2_id
                        events2_data['event_name'] = event2_data.item
                        events2_data['event_imageUrl'] = img2.img
                        output2.append(events2_data)
                    if event3_data:
                        events3_data['event_id'] = events.item3_id
                        events3_data['event_name'] = event3_data.item
                        events3_data['event_imageUrl'] = img3.img
                        output2.append(events3_data)
                    if event4_data:
                        events4_data['event_id'] = events.item4_id
                        events4_data['event_name'] = event4_data.item
                        events4_data['event_imageUrl'] = img4.img
                        output2.append(events4_data)
                    if event5_data:
                        events5_data['event_id'] = events.item5_id
                        events5_data['event_name'] = event5_data.item
                        events5_data['event_imageUrl'] = img5.img
                        output2.append(events5_data)
                    if event6_data:
                        events6_data['event_id'] = events.item6_id
                        events6_data['event_name'] = event6_data.item
                        events6_data['event_imageUrl'] = img6.img
                        output2.append(events6_data)

                    if event7_data:
                        events7_data['event_id'] = events.item7_id
                        events7_data['event_name'] = event7_data.item
                        events7_data['event_imageUrl'] = img7.img
                        output2.append(events7_data)
                    if event8_data:
                        events8_data['event_id'] = events.item8_id
                        events8_data['event_name'] = event8_data.item
                        events8_data['event_imageUrl'] = img8.img
                        output2.append(events8_data)

            aesthetics = userAesthetics.query.filter_by(users_id=user.id).first()
            if not aesthetics:
                aesthetics_data = {}
                aesthetics_data['message_Aesthetics'] = "there is no Aesthetics yet, try to add your favourite Aesthetics"


            else:
                aesthetic1_data = fullAesthetics.query.filter_by(id=aesthetics.item1_id).first()
                aesthetic2_data = fullAesthetics.query.filter_by(id=aesthetics.item2_id).first()
                aesthetic3_data = fullAesthetics.query.filter_by(id=aesthetics.item3_id).first()
                aesthetic4_data = fullAesthetics.query.filter_by(id=aesthetics.item4_id).first()
                aesthetic5_data = fullAesthetics.query.filter_by(id=aesthetics.item5_id).first()
                aesthetic6_data = fullAesthetics.query.filter_by(id=aesthetics.item6_id).first()
                aesthetic7_data = fullAesthetics.query.filter_by(id=aesthetics.item7_id).first()
                aesthetic8_data = fullAesthetics.query.filter_by(id=aesthetics.item8_id).first()

                if aesthetic1_data:
                    img1 = Img.query.filter_by(id=aesthetic1_data.image_id).first()
                if aesthetic2_data:
                    img2 = Img.query.filter_by(id=aesthetic2_data.image_id).first()
                if aesthetic3_data:
                    img3 = Img.query.filter_by(id=aesthetic3_data.image_id).first()
                if aesthetic4_data:
                    img4 = Img.query.filter_by(id=aesthetic4_data.image_id).first()
                if aesthetic5_data:
                    img5 = Img.query.filter_by(id=aesthetic5_data.image_id).first()
                if aesthetic6_data:
                    img6 = Img.query.filter_by(id=aesthetic6_data.image_id).first()
                if aesthetic7_data:
                    img7 = Img.query.filter_by(id=aesthetic7_data.image_id).first()
                if aesthetic8_data:
                    img8 = Img.query.filter_by(id=aesthetic8_data.image_id).first()

                output3 = []
                aesthetics1_data = {}
                aesthetics2_data = {}
                aesthetics3_data = {}
                aesthetics4_data = {}
                aesthetics5_data = {}
                aesthetics6_data = {}
                aesthetics7_data = {}
                aesthetics8_data = {}

                if aesthetic1_data:
                    aesthetics1_data['aesthetic_id'] = aesthetics.item1_id
                    aesthetics1_data['aesthetic_name'] = aesthetic1_data.item
                    aesthetics1_data['aesthetic_imageUrl'] = img1.img
                    output3.append(aesthetics1_data)
                if aesthetic2_data:
                    aesthetics2_data['aesthetic_id'] = aesthetics.item2_id
                    aesthetics2_data['aesthetic_name'] = aesthetic2_data.item
                    aesthetics2_data['aesthetic_imageUrl'] = img2.img
                    output3.append(aesthetics2_data)
                if aesthetic3_data:
                    aesthetics3_data['aesthetic_id'] = aesthetics.item3_id
                    aesthetics3_data['aesthetic_name'] = aesthetic3_data.item
                    aesthetics3_data['aesthetic_imageUrl'] = img3.img
                    output3.append(aesthetics3_data)
                if aesthetic4_data:
                    aesthetics4_data['aesthetic_id'] = aesthetics.item4_id
                    aesthetics4_data['aesthetic_name'] = aesthetic4_data.item
                    aesthetics4_data['aesthetic_imageUrl'] = img4.img
                    output3.append(aesthetics4_data)
                if aesthetic5_data:
                    aesthetics5_data['aesthetic_id'] = aesthetics.item5_id
                    aesthetics5_data['aesthetic_name'] = aesthetic5_data.item
                    aesthetics5_data['aesthetic_imageUrl'] = img5.img
                    output3.append(aesthetics5_data)
                if aesthetic6_data:
                    aesthetics6_data['aesthetic_id'] = aesthetics.item6_id
                    aesthetics6_data['aesthetic_name'] = aesthetic6_data.item
                    aesthetics6_data['aesthetic_imageUrl'] = img6.img
                    output3.append(aesthetics6_data)

                if aesthetic7_data:
                    aesthetics7_data['aesthetic_id'] = aesthetics.item7_id
                    aesthetics7_data['aesthetic_name'] = aesthetic7_data.item
                    aesthetics7_data['aesthetic_imageUrl'] = img7.img
                    output3.append(aesthetics7_data)
                if aesthetic8_data:
                    aesthetics8_data['aesthetic_id'] = aesthetics.item8_id
                    aesthetics8_data['aesthetic_name'] = aesthetic8_data.item
                    aesthetics8_data['aesthetic_imageUrl'] = img8.img
                    output3.append(aesthetics8_data)


            return jsonify({'My items': output, "My events" : output2, "My Aethetics" : output3 })

          #------------------------------SEARCH--------------------------------

@views.route('/Search/<username>',methods=['GET'])
@token_required
def SearchForPeople(current_user,username):
    user=Users.query.filter_by(username=username).first()
    if user:
        profile= Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()
        user_data={}
        user_data['username']=user.username
        if profile:
            user_data['image_url']=im.img
        user_data['user_id']=user.id
        return jsonify({'user_data': user_data})

@views.route('/<user_id>/profile_Page/profile_Info', methods=['POST', 'GET'])
@token_required
def search_getProfileInfo(current_user,user_id):
            user = Users.query.filter_by(id=user_id).first()
            profile = Profile.query.filter_by(user_id=user.id).first()
            if profile:
                im = Img.query.filter_by(id=profile.image_id).first()
            bioAndlinks = Profile.query.filter_by(user_id=user.id).first()
            postCount = Posts.query.filter_by(user_id=user.id).count()
            followingCount = Followers.query.filter_by(follower_id=user.id).count()
            followersCount = Followers.query.filter_by(followed_id=user.id).count()
            user_data = {}
            user_data['user_id'] = user.id
            if profile:
                user_data['image_url'] = im.img
            user_data['username'] = user.username
            if not bioAndlinks:
                user_data['bio'] = "you can add your bio"
            else:
                user_data['bio'] = bioAndlinks.bio
                user_data['fb_link'] = bioAndlinks.fb_link
                user_data['ig_link'] = bioAndlinks.ig_link
                user_data['pinterest_link'] = bioAndlinks.pinterest_link
            user_data['following Num'] = followingCount
            user_data['followers Num'] = followersCount
            user_data['num of posts'] = postCount
            # user_data['profilePosts_link'] = "http://127.0.0.1:5001/profile_Page/profile_Posts"
            # user_data['profileFavorites_link'] = "http://127.0.0.1:5001/profile_Page/profile_Favorites"
            # user_data['profileCategories_link'] = "http://127.0.0.1:5001/profile_Page/profile_Categories"

            return jsonify({'My Profile Info': user_data})

@views.route('<user_id>/profile_Page/profile_Posts', methods=['POST', 'GET'])
@token_required
def search_getProfilePosts(current_user,user_id):
            user = Users.query.filter_by(id=user_id).first()
            profile = Profile.query.filter_by(user_id=user.id).first()
            if profile:
                im = Img.query.filter_by(id=profile.image_id).first()

            posts = Posts.query.filter_by(user_id=user.id).all()
            if not posts:
                post_data = {}
                post_data['message'] = 'there is no posts of you yet,, Try to post something '

            post_output = []
            for post in posts:
                imgg = Img.query.filter_by(id=post.image_id).first()
                numOfLikes = PostLike.query.filter_by(post_id=post.id).count()
                numOfComments = PostComment.query.filter_by(post_id=post.id).count()
                numOfSharing = SharePost.query.filter_by(post_id=post.id).count()

                post_data = {}
                post_data['by'] = user.username
                if profile:
                    post_data['user profile pic'] = im.img
                post_data['timePosted'] = post.date
                post_data['location'] = post.location
                post_data['image_url'] = imgg.img
                post_data['desc'] = post.desc
                post_data['num of likes'] = numOfLikes
                post_data['num of Comments'] = numOfComments
                post_data['num of Sharing'] = numOfSharing
                post_data['post_id'] = post.id
                post_output.append(post_data)
            return jsonify({'My Posts': post_output})

@views.route('<user_id>/profile_Page/profile_Favorites', methods=['POST', 'GET'])
@token_required
def search_getProfileFavorites(current_user,user_id):
            user = Users.query.filter_by(id=user_id).first()
            likes = PostLike.query.filter_by(users_id=user.id).all()
            if not likes:
                return jsonify({'messgae': 'there is no posts u like yet'})
            else:
                post_output = []
                for like in likes:
                    post = Posts.query.filter_by(id=like.post_id).first()
                    userr = Users.query.filter_by(id=post.user_id).first()
                    profile = Profile.query.filter_by(user_id=userr.id).first()
                    if profile:
                        im = Img.query.filter_by(id=profile.image_id).first()
                    imgg = Img.query.filter_by(id=post.image_id).first()
                    numOfLikes = PostLike.query.filter_by(post_id=post.id).count()
                    numOfComments = PostComment.query.filter_by(post_id=post.id).count()
                    numOfSharing = SharePost.query.filter_by(post_id=post.id).count()
                    post_data = {}
                    post_data['by'] = userr.username
                    if profile:
                        post_data['user profile pic'] = im.img
                    post_data['timePosted'] = post.date
                    post_data['location'] = post.location
                    post_data['image_url'] = imgg.img
                    post_data['desc'] = post.desc
                    post_data['num of likes'] = numOfLikes
                    post_data['num of Comments'] = numOfComments
                    post_data['num of Sharing'] = numOfSharing
                    post_data['post_id'] = post.id
                    post_output.append(post_data)
                return jsonify({'My Favorites': post_output})

@views.route('<userId>/profile_Page/profile_Categories', methods=['POST', 'GET'])
@token_required
def search_getProfileCategories(current_user,userId):
            user = Users.query.filter_by(id=userId).first()
            interests = userInterests.query.filter_by(users_id=user.id).first()
            if not interests:
                interests_data = {}
                interests_data['message_items'] = "there is no items yet, try to add your favourite items!"


            else :
                interest1_data=fullInterests.query.filter_by(id=interests.item1_id).first()
                interest2_data=fullInterests.query.filter_by(id=interests.item2_id).first()
                interest3_data=fullInterests.query.filter_by(id=interests.item3_id).first()
                interest4_data=fullInterests.query.filter_by(id=interests.item4_id).first()
                interest5_data=fullInterests.query.filter_by(id=interests.item5_id).first()
                interest6_data=fullInterests.query.filter_by(id=interests.item6_id).first()
                interest7_data=fullInterests.query.filter_by(id=interests.item7_id).first()
                interest8_data=fullInterests.query.filter_by(id=interests.item8_id).first()
                interest9_data=fullInterests.query.filter_by(id=interests.item9_id).first()
                interest10_data=fullInterests.query.filter_by(id=interests.item10_id).first()
                interest11_data=fullInterests.query.filter_by(id=interests.item11_id).first()
                interest12_data=fullInterests.query.filter_by(id=interests.item12_id).first()
                interest13_data=fullInterests.query.filter_by(id=interests.item13_id).first()

                if interest1_data:
                    img1=Img.query.filter_by(id=interest1_data.image_id).first()
                if interest2_data:
                    img2=Img.query.filter_by(id=interest2_data.image_id).first()
                if interest3_data:
                    img3=Img.query.filter_by(id=interest3_data.image_id).first()
                if interest4_data:
                    img4=Img.query.filter_by(id=interest4_data.image_id).first()
                if interest5_data:
                    img5=Img.query.filter_by(id=interest5_data.image_id).first()
                if interest6_data:
                    img6=Img.query.filter_by(id=interest6_data.image_id).first()
                if interest7_data:
                    img7=Img.query.filter_by(id=interest7_data.image_id).first()
                if interest8_data:
                    img8=Img.query.filter_by(id=interest8_data.image_id).first()
                if interest9_data:
                    img9=Img.query.filter_by(id=interest9_data.image_id).first()
                if interest10_data:
                    img10=Img.query.filter_by(id=interest10_data.image_id).first()
                if interest11_data:
                    img11=Img.query.filter_by(id=interest11_data.image_id).first()
                if interest12_data:
                    img12=Img.query.filter_by(id=interest12_data.image_id).first()
                if interest13_data:
                    img13=Img.query.filter_by(id=interest13_data.image_id).first()

                output = []
                if interest1_data:
                    interests1_data = {}
                    interests1_data['item_id'] = interests.item1_id
                    interests1_data['item_name'] = interest1_data.item
                    interests1_data['item_imageUrl'] = img1.img
                    output.append(interests1_data)
                if interest2_data:
                    interests2_data = {}
                    interests2_data['item_id'] = interests.item2_id
                    interests2_data['item_name'] = interest2_data.item
                    interests2_data['item_imageUrl'] = img2.img
                    output.append(interests2_data)
                if interest3_data:
                    interests3_data = {}
                    interests3_data['item_id'] = interests.item3_id
                    interests3_data['item_name'] = interest3_data.item
                    interests3_data['item_imageUrl'] = img3.img
                    output.append(interests3_data)
                if interest4_data:
                    interests4_data = {}
                    interests4_data['item_id'] = interests.item4_id
                    interests4_data['item_name'] = interest4_data.item
                    interests4_data['item_imageUrl'] = img4.img
                    output.append(interests4_data)
                if interest5_data:
                    interests5_data = {}
                    interests5_data['item_id'] = interests.item5_id
                    interests5_data['item_name'] = interest5_data.item
                    interests5_data['item_imageUrl'] = img5.img
                    output.append(interests5_data)
                if interest6_data:
                    interests6_data = {}
                    interests6_data['item_id'] = interests.item6_id
                    interests6_data['item_name'] = interest6_data.item
                    interests6_data['item_imageUrl'] = img6.img
                    output.append(interests6_data)

                if interest7_data:
                    interests7_data = {}
                    interests7_data['item_id'] = interests.item7_id
                    interests7_data['item_name'] = interest7_data.item
                    interests7_data['item_imageUrl'] = img7.img
                    output.append(interests7_data)
                if interest8_data:
                    interests8_data = {}
                    interests8_data['item_id'] = interests.item8_id
                    interests8_data['item_name'] = interest8_data.item
                    interests8_data['item_imageUrl'] = img8.img
                    output.append(interests8_data)
                if interest9_data:
                    interests9_data = {}
                    interests9_data['item_id'] = interests.item9_id
                    interests9_data['item_name'] = interest9_data.item
                    interests9_data['item_imageUrl'] = img9.img
                    output.append(interests9_data)
                if interest10_data:
                    interests10_data = {}
                    interests10_data['item_id'] = interests.item10_id
                    interests10_data['item_name'] = interest10_data.item
                    interests10_data['item_imageUrl'] = img10.img
                    output.append(interests10_data)
                if interest11_data:
                    interests11_data = {}
                    interests11_data['item_id'] = interests.item11_id
                    interests11_data['item_name'] = interest11_data.item
                    interests11_data['item_imageUrl'] = img11.img
                    output.append(interests11_data)
                if interest12_data:
                    interests12_data = {}
                    interests12_data['item_id'] = interests.item12_id
                    interests12_data['item_name'] = interest12_data.item
                    interests12_data['item_imageUrl'] = img12.img
                    output.append(interests12_data)
                if interest13_data:
                    interests13_data = {}
                    interests13_data['item_id'] = interests.item13_id
                    interests13_data['item_name'] = interest13_data.item
                    interests13_data['item_imageUrl'] = img13.img
                    output.append(interests13_data)

            events = userEvents.query.filter_by(users_id=user.id).first()
            if not events:
                    events_data = {}
                    events_data['message_events'] = "there is no events yet, try to add your favourite events"


            else:
                    event1_data = fullEvents.query.filter_by(id=events.item1_id).first()
                    event2_data = fullEvents.query.filter_by(id=events.item2_id).first()
                    event3_data = fullEvents.query.filter_by(id=events.item3_id).first()
                    event4_data = fullEvents.query.filter_by(id=events.item4_id).first()
                    event5_data = fullEvents.query.filter_by(id=events.item5_id).first()
                    event6_data = fullEvents.query.filter_by(id=events.item6_id).first()
                    event7_data = fullEvents.query.filter_by(id=events.item7_id).first()
                    event8_data = fullEvents.query.filter_by(id=events.item8_id).first()

                    if event1_data:
                        img1 = Img.query.filter_by(id=event1_data.image_id).first()
                    if event2_data:
                        img2 = Img.query.filter_by(id=event2_data.image_id).first()
                    if event3_data:
                        img3 = Img.query.filter_by(id=event3_data.image_id).first()
                    if event4_data:
                        img4 = Img.query.filter_by(id=event4_data.image_id).first()
                    if event5_data:
                        img5 = Img.query.filter_by(id=event5_data.image_id).first()
                    if event6_data:
                        img6 = Img.query.filter_by(id=event6_data.image_id).first()
                    if event7_data:
                        img7 = Img.query.filter_by(id=event7_data.image_id).first()
                    if event8_data:
                        img8 = Img.query.filter_by(id=event8_data.image_id).first()


                    output2 = []
                    events1_data = {}
                    events2_data = {}
                    events3_data = {}
                    events4_data = {}
                    events5_data = {}
                    events6_data = {}
                    events7_data = {}
                    events8_data = {}

                    if event1_data:
                        events1_data['event_id'] = events.item1_id
                        events1_data['event_name'] = event1_data.item
                        events1_data['event_imageUrl'] = img1.img
                        output2.append(events1_data)
                    if event2_data:
                        events2_data['event_id'] = events.item2_id
                        events2_data['event_name'] = event2_data.item
                        events2_data['event_imageUrl'] = img2.img
                        output2.append(events2_data)
                    if event3_data:
                        events3_data['event_id'] = events.item3_id
                        events3_data['event_name'] = event3_data.item
                        events3_data['event_imageUrl'] = img3.img
                        output2.append(events3_data)
                    if event4_data:
                        events4_data['event_id'] = events.item4_id
                        events4_data['event_name'] = event4_data.item
                        events4_data['event_imageUrl'] = img4.img
                        output2.append(events4_data)
                    if event5_data:
                        events5_data['event_id'] = events.item5_id
                        events5_data['event_name'] = event5_data.item
                        events5_data['event_imageUrl'] = img5.img
                        output2.append(events5_data)
                    if event6_data:
                        events6_data['event_id'] = events.item6_id
                        events6_data['event_name'] = event6_data.item
                        events6_data['event_imageUrl'] = img6.img
                        output2.append(events6_data)

                    if event7_data:
                        events7_data['event_id'] = events.item7_id
                        events7_data['event_name'] = event7_data.item
                        events7_data['event_imageUrl'] = img7.img
                        output2.append(events7_data)
                    if event8_data:
                        events8_data['event_id'] = events.item8_id
                        events8_data['event_name'] = event8_data.item
                        events8_data['event_imageUrl'] = img8.img
                        output2.append(events8_data)

            aesthetics = userAesthetics.query.filter_by(users_id=user.id).first()
            if not aesthetics:
                aesthetics_data = {}
                aesthetics_data['message_Aesthetics'] = "there is no Aesthetics yet, try to add your favourite Aesthetics"


            else:
                aesthetic1_data = fullAesthetics.query.filter_by(id=aesthetics.item1_id).first()
                aesthetic2_data = fullAesthetics.query.filter_by(id=aesthetics.item2_id).first()
                aesthetic3_data = fullAesthetics.query.filter_by(id=aesthetics.item3_id).first()
                aesthetic4_data = fullAesthetics.query.filter_by(id=aesthetics.item4_id).first()
                aesthetic5_data = fullAesthetics.query.filter_by(id=aesthetics.item5_id).first()
                aesthetic6_data = fullAesthetics.query.filter_by(id=aesthetics.item6_id).first()
                aesthetic7_data = fullAesthetics.query.filter_by(id=aesthetics.item7_id).first()
                aesthetic8_data = fullAesthetics.query.filter_by(id=aesthetics.item8_id).first()

                if aesthetic1_data:
                    img1 = Img.query.filter_by(id=aesthetic1_data.image_id).first()
                if aesthetic2_data:
                    img2 = Img.query.filter_by(id=aesthetic2_data.image_id).first()
                if aesthetic3_data:
                    img3 = Img.query.filter_by(id=aesthetic3_data.image_id).first()
                if aesthetic4_data:
                    img4 = Img.query.filter_by(id=aesthetic4_data.image_id).first()
                if aesthetic5_data:
                    img5 = Img.query.filter_by(id=aesthetic5_data.image_id).first()
                if aesthetic6_data:
                    img6 = Img.query.filter_by(id=aesthetic6_data.image_id).first()
                if aesthetic7_data:
                    img7 = Img.query.filter_by(id=aesthetic7_data.image_id).first()
                if aesthetic8_data:
                    img8 = Img.query.filter_by(id=aesthetic8_data.image_id).first()

                output3 = []
                aesthetics1_data = {}
                aesthetics2_data = {}
                aesthetics3_data = {}
                aesthetics4_data = {}
                aesthetics5_data = {}
                aesthetics6_data = {}
                aesthetics7_data = {}
                aesthetics8_data = {}

                if aesthetic1_data:
                    aesthetics1_data['aesthetic_id'] = aesthetics.item1_id
                    aesthetics1_data['aesthetic_name'] = aesthetic1_data.item
                    aesthetics1_data['aesthetic_imageUrl'] = img1.img
                    output3.append(aesthetics1_data)
                if aesthetic2_data:
                    aesthetics2_data['aesthetic_id'] = aesthetics.item2_id
                    aesthetics2_data['aesthetic_name'] = aesthetic2_data.item
                    aesthetics2_data['aesthetic_imageUrl'] = img2.img
                    output3.append(aesthetics2_data)
                if aesthetic3_data:
                    aesthetics3_data['aesthetic_id'] = aesthetics.item3_id
                    aesthetics3_data['aesthetic_name'] = aesthetic3_data.item
                    aesthetics3_data['aesthetic_imageUrl'] = img3.img
                    output3.append(aesthetics3_data)
                if aesthetic4_data:
                    aesthetics4_data['aesthetic_id'] = aesthetics.item4_id
                    aesthetics4_data['aesthetic_name'] = aesthetic4_data.item
                    aesthetics4_data['aesthetic_imageUrl'] = img4.img
                    output3.append(aesthetics4_data)
                if aesthetic5_data:
                    aesthetics5_data['aesthetic_id'] = aesthetics.item5_id
                    aesthetics5_data['aesthetic_name'] = aesthetic5_data.item
                    aesthetics5_data['aesthetic_imageUrl'] = img5.img
                    output3.append(aesthetics5_data)
                if aesthetic6_data:
                    aesthetics6_data['aesthetic_id'] = aesthetics.item6_id
                    aesthetics6_data['aesthetic_name'] = aesthetic6_data.item
                    aesthetics6_data['aesthetic_imageUrl'] = img6.img
                    output3.append(aesthetics6_data)

                if aesthetic7_data:
                    aesthetics7_data['aesthetic_id'] = aesthetics.item7_id
                    aesthetics7_data['aesthetic_name'] = aesthetic7_data.item
                    aesthetics7_data['aesthetic_imageUrl'] = img7.img
                    output3.append(aesthetics7_data)
                if aesthetic8_data:
                    aesthetics8_data['aesthetic_id'] = aesthetics.item8_id
                    aesthetics8_data['aesthetic_name'] = aesthetic8_data.item
                    aesthetics8_data['aesthetic_imageUrl'] = img8.img
                    output3.append(aesthetics8_data)


            return jsonify({'My items': output, "My events" : output2, "My Aethetics" : output3 })

        #------------------------------POSTS--------------------------------



@views.route('/createPost',methods=['GET','POST'])
@token_required
def createPost(current_user):
    if request.method == 'POST':

        imageType="Post_Image"
        image_id = upload(current_user,request,imageType)

        data=request.form
        desc = data["desc"]
        location = data["location"]


        newPost = Posts(user_id=current_user.id, desc=desc, location=location,image_id=image_id)
        print(newPost)
        db.session.add(newPost)
        db.session.commit()
        return jsonify({'message' : 'new post is created successfully'})


@views.route('/posts',methods=['POST', 'GET'])
@token_required
def posts(current_user):
    posts = Posts.query.all()
    if not posts:
       return jsonify({'message': 'There is no posts yet .. Try to post something!'})
    output = []
    for post in posts:
        user=Users.query.filter_by(id=post.user_id).first()
        profile = Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()
        imgg=Img.query.filter_by(id=post.image_id).first()
        print(user.username)
        post_data = {}
        post_data['by'] = user.username
        if profile:
           post_data['user profile pic'] = im.img
        post_data['image_url'] = imgg.img
        post_data['desc'] = post.desc
        post_data['location'] = post.location
        post_data['date'] = post.date
        post_data['post_id'] = post.id
        output.append(post_data)
    return jsonify({'the list of posts':output})

@views.route('/post/<id>', methods=['get'])
@token_required
def getPost(current_user, id):
        post = Posts.query.filter_by(id=id).first()
        if not post:
            return jsonify({'message': 'post does not exist'})

        imgg=Img.query.filter_by(id=post.image_id).first()

        user=Users.query.filter_by(id=post.user_id).first()
        profile = Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()
        post_data = {}
        post_data['by'] = user.username
        if profile:
           post_data['user profile pic'] = im.img
        post_data['location'] = post.location
        post_data['image_url'] = imgg.img
        post_data['desc'] = post.desc
        post_data['date'] = post.date
        #post_data['likes']
        # post_data['comments']

        return jsonify({'post data': post_data })


@views.route('/posts/<id>', methods=['DELETE'])
@token_required
def deletePost(current_user,id):
    post = Posts.query.filter_by(id=id, user_id=current_user.id).first()
    if not post:
       return jsonify({'message': 'post does not exist'})
    db.session.delete(post)
    db.session.commit()

    return jsonify({'message': 'Post is deleted'})


      #-------------------------------TIPS------------------------------

@views.route('/createTip', methods=['GET', 'POST'])
@token_required
def createTip(current_user):
        if request.method == 'POST':
            imageType = "Tip_Image"
            image_id = upload(current_user, request, imageType)

            data = request.form
            caption = data["caption"]

            newTip = Tips(user_id=current_user.id, caption=caption, image_id=image_id)
            db.session.add(newTip)
            db.session.commit()
            return jsonify({'message': 'new Tip is created successfully'})

@views.route('/tips', methods=['POST', 'GET'])
@token_required
def tips(current_user):
        tips = Tips.query.all()
        if not tips:
            return jsonify({'message': 'There is no tips yet .. Try to post a tip!'})
        output = []
        for tip in tips:
            user = Users.query.filter_by(id=tip.user_id).first()
            ratings = Ratings.query.filter_by(tip_id=tip.id).count()
            if ratings:
                star1_rating = Ratings.query.filter_by(tip_id=tip.id, star1_id=1, star2_id='').count()
                star2_rating = Ratings.query.filter_by(tip_id=tip.id, star2_id=2, star3_id='').count()
                star3_rating = Ratings.query.filter_by(tip_id=tip.id, star3_id=3, star4_id='').count()
                star4_rating = Ratings.query.filter_by(tip_id=tip.id, star4_id=4, star5_id='').count()
                star5_rating = Ratings.query.filter_by(tip_id=tip.id, star5_id=5).count()
                avgRating = (5*star5_rating + 4*star4_rating + 3*star3_rating + 2*star2_rating + 1*star1_rating)/ratings
            profile = Profile.query.filter_by(user_id=user.id).first()
            if profile:
                im = Img.query.filter_by(id=profile.image_id).first()
            imgg = Img.query.filter_by(id=tip.image_id).first()
            tip_data = {}
            tip_data['by'] = user.username
            if profile:
                tip_data['user profile pic'] = im.img
            tip_data['image_url'] = imgg.img
            tip_data['caption'] = tip.caption
            tip_data['date'] = tip.date
            tip_data['tip_id'] = tip.id
            if ratings:
                tip_data['ratings'] = ratings
                tip_data['Average_rating'] = avgRating
            else:
                tip_data['ratings'] = 0
                tip_data['Average_rating'] = 0.0
            output.append(tip_data)
        return jsonify({'the list of tips': output})
#
@views.route('/tip/<id>', methods=['get'])
@token_required
def getTip(current_user, id):
        tip = Tips.query.filter_by(id=id).first()
        if not tip:
            return jsonify({'message': 'tip does not exist'})

        user = Users.query.filter_by(id=tip.user_id).first()
        profile = Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()
        imgg = Img.query.filter_by(id=tip.image_id).first()
        tip_data = {}
        tip_data['by'] = user.username
        if profile:
           tip_data['user profile pic'] = im.img
        tip_data['tip Image'] = imgg.img
        tip_data['caption'] = tip.caption
        tip_data['date'] = tip.date
        # tip_data['ratings']

        return jsonify({'tip data': tip_data})
#
@views.route('/tip/<id>', methods=['DELETE'])
@token_required
def deleteTip(current_user, id):
        tip = Tips.query.filter_by(id=id, user_id=current_user.id).first()
        if not tip:
            return jsonify({'message': 'tip does not exist'})
        db.session.delete(tip)
        db.session.commit()

        return jsonify({'message': 'Tip is deleted'})


     # -------------------------------RATINGS ON TIPS------------------------------

@views.route('/rate/<tip_id>/<star_id>', methods=['POST'])
@token_required
def Rate_action(current_user,tip_id,star_id):
    tip = Tips.query.filter_by(id=tip_id).first()
    s= Stars.query.filter_by(id=star_id).first()
    if s.id==1:
        rating = Ratings(users_id=current_user.id, tip_id=tip.id, star1_id=s.id,star2_id='',star3_id='',star4_id='',star5_id='')
        db.session.add(rating)
        db.session.commit()


    if s.id==2:
        rating = Ratings(users_id=current_user.id, tip_id=tip.id, star1_id=1,star2_id=s.id,star3_id='',star4_id='',star5_id='')
        db.session.add(rating)
        db.session.commit()

    if s.id==3:
        rating = Ratings(users_id=current_user.id, tip_id=tip.id, star1_id='1',star2_id='2',star3_id=s.id,star4_id='',star5_id='')
        db.session.add(rating)
        db.session.commit()


    if s.id==4:
        rating = Ratings(users_id=current_user.id, tip_id=tip.id, star1_id='1',star2_id='2',star3_id='3',star4_id=s.id,star5_id='')
        db.session.add(rating)
        db.session.commit()


    if s.id==5:
        rating = Ratings(users_id=current_user.id, tip_id=tip.id, star1_id='1',star2_id='2',star3_id='3',star4_id='4',star5_id=s.id)
        db.session.add(rating)
        db.session.commit()

    # THEN ADD TO NOTIFICATION

    user = Users.query.filter_by(id=current_user.id).first()
    new_notification = Notifications(receiver_user_id=tip.user_id, sender_user_id=user.id,
                                     notificationText=" your tip was rated "+ str(s.id) +" stars from " +user.username, read=False,
                                     type="rate")
    db.session.add(new_notification)
    db.session.commit()

    return jsonify({'message': user.username +' has rated on this tip!'})

    # -------------------------------POLLS------------------------------

@views.route('/createPoll', methods=['GET', 'POST'])
@token_required
def createPoll(current_user):
        if request.method == 'POST':
            image1Type = "Poll_Image1"
            image2Type = "Poll_Image2"
            image1_id = upload(current_user, request, image1Type)
            image2_id = upload2(current_user, request, image2Type)

            data = request.form

            caption = data["caption"]

            newPoll = Polls(user_id=current_user.id, caption=caption, image1_id=image1_id,image2_id=image2_id)
            print(newPoll)
            db.session.add(newPoll)
            db.session.commit()
            return jsonify({'message': 'new Poll is created successfully'})


@views.route('/polls', methods=['POST', 'GET'])
@token_required
def polls(current_user):
        polls = Polls.query.all()
        if not polls:
            return jsonify({'message': 'There is no polls yet .. Try to post a poll!'})
        output = []
        for poll in polls:

            user = Users.query.filter_by(id=poll.user_id).first()
            profile = Profile.query.filter_by(user_id=user.id).first()
            if profile:
                im = Img.query.filter_by(id=profile.image_id).first()
            imgg = Img.query.filter_by(id=poll.image1_id).first()
            imgg2 = Img.query.filter_by(id=poll.image2_id).first()
            votes=Voting.query.filter_by(poll_id=poll.id).first()
            if not votes:
                votes={}
                votes['votes']=0
            votes_image1=Voting.query.filter_by(poll_id=poll.id,image_id=imgg.id).count()
            # if not votes_image1:
            #     votes_image1={}
            #     votes_image1['votes_image1']=0
            votes_image2=Voting.query.filter_by(poll_id=poll.id,image_id=imgg2.id).count()
            # if not votes_image2:
            #     votes_image2={}
            #     votes_image2['votes_image2']=0


            print(user.username)
            poll_data = {}
            poll_data['by'] = user.username
            if profile:
               poll_data['user profile pic'] = im.img
            poll_data['image1_url'] = imgg.img
            poll_data['image2_url'] = imgg2.img
            poll_data['poll_id'] = poll.id
            poll_data['image1_id'] = imgg.id
            poll_data['image2_id'] = imgg2.id
            poll_data['caption'] = poll.caption
            poll_data['date'] = poll.creation_date
            if votes_image1:
                poll_data['votes on image1'] = votes_image1
            else:
                poll_data['votes on image1'] = 0

            if votes_image2:
                poll_data['votes on image2'] = votes_image2
            else:
                poll_data['votes on image2'] = 0


            output.append(poll_data)
        return jsonify({'the list of polls': output})
# #
@views.route('/poll/<id>', methods=['get'])
@token_required
def getPoll(current_user, id):
        poll = Polls.query.filter_by(id=id).first()
        if not poll:
            return jsonify({'message': 'poll does not exist'})

        user = Users.query.filter_by(id=poll.user_id).first()
        profile = Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()
        imgg = Img.query.filter_by(id=poll.image1_id).first()
        imgg2 = Img.query.filter_by(id=poll.image2_id).first()
        votes = Voting.query.filter_by(poll_id=poll.id).first()
        if not votes:
            votes = {}
            votes['votes'] = 0
        votes_image1 = Voting.query.filter_by(poll_id=poll.id, image_id=imgg.id).count()
        votes_image2 = Voting.query.filter_by(poll_id=poll.id, image_id=imgg2.id).count()

        poll_data = {}
        poll_data['by'] = user.username
        if profile:
            poll_data['user profile pic'] = im.img
        poll_data['image1_url'] = imgg.img
        poll_data['image2_url'] = imgg2.img
        poll_data['caption'] = poll.caption
        poll_data['date'] = poll.creation_date
        if votes_image1:
            poll_data['votes on image1'] = votes_image1
        else:
            poll_data['votes on image1'] = 0

        if votes_image2:
            poll_data['votes on image2'] = votes_image2
        else:
            poll_data['votes on image2'] = 0

        # tip_data['voting']
        return jsonify({'poll data': poll_data})
# #
@views.route('/poll/<id>', methods=['DELETE'])
@token_required
def deletePoll(current_user, id):
        poll = Polls.query.filter_by(id=id, user_id=current_user.id).first()
        if not poll:
            return jsonify({'message': 'poll does not exist'})
        db.session.delete(poll)
        db.session.commit()

        return jsonify({'message': 'Poll is deleted'})

    # -------------------------------VOTING ON POLLS------------------------------

@views.route('/vote/<poll_id>', methods=['POST','GET'])
@token_required
def vote_action(current_user,poll_id):

        poll = Polls.query.filter_by(id=poll_id).first()
        data = request.get_json()
        image_id = data['image_id']
        voting = Voting(users_id=current_user.id, poll_id=poll.id, image_id=image_id)
        db.session.add(voting)
        db.session.commit()
        votesCount = Voting.query.filter_by(poll_id=poll.id).count()
        if str(image_id)==str(poll.image1_id):

            votes_image1= Voting.query.filter_by(poll_id=poll.id,image_id=image_id).count()
            if votes_image1:
                votes_image1_ratio= (votes_image1 /votesCount) * 100
        elif str(image_id)==str(poll.image2_id):
            votes_image2= Voting.query.filter_by(poll_id=poll.id,image_id=image_id).count()
            if votes_image2:
                votes_image2_ratio = (votes_image2 /votesCount) * 100
        else:
            return jsonify({'message':'please vote on the right picture'})
        user=Users.query.filter_by(id=poll.user_id).first()
        profile = Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()
        poll_image_data = {}
        poll_image_data['by'] = user.username
        if profile:
            poll_image_data['user profile pic'] = im.img
        if str(image_id) == str(poll.image1_id):
            imgg=Img.query.filter_by(id=image_id).first()
            poll_image_data['image1 url']=imgg.img
            if votes_image1:
                poll_image_data['votesImage1 ratio']=votes_image1_ratio
            else:
                poll_image_data['votesImage1 ratio'] =0

        if str(image_id) == str(poll.image2_id):
            imgg=Img.query.filter_by(id=image_id).first()
            poll_image_data['image2 url']=imgg.img
            if votes_image2:
                poll_image_data['votesImage2 ratio']=votes_image2_ratio
            else:
                poll_image_data['votesImage2 ratio'] =0

        # THEN ADD TO NOTIFICATION


        user = Users.query.filter_by(id=current_user.id).first()
        new_notification = Notifications(receiver_user_id=poll.user_id, sender_user_id=user.id,
                                             notificationText="your poll was voted by "+user.username+" ,total votes are "+str(votesCount)+" times", read=False,type= "vote")
        db.session.add(new_notification)
        db.session.commit()

        return jsonify({'message': user.username + ' has voted on your poll! ', 'poll_image_data':poll_image_data})

@views.route('/vote/<int:poll_id>/viewVotes',methods=['GET'])
@token_required
def viewVotes(current_user,poll_id):
    poll = Polls.query.filter_by(id=poll_id).first()
    votes = []
    for voter in poll.get_votes():
        user = Users.query.filter_by(id = voter.users_id).first()
        votes.append({
            'users_id': voter.users_id,
            'name': user.username,
            'poll_id': voter.poll_id,
            'image_id': voter.image_id
        })
    return jsonify({
        'Votes': votes
    })



    # -------------------------------DISCOVER PAGE------------------------------

@views.route('/Discover_Page',methods=['POST', 'GET'])
@token_required
def DiscoverPage(current_user):


    user = userInterests.query.filter_by(users_id=current_user.id).first()
    user_output = []
    if user:
            otherUsers= userInterests.query.filter_by(item1_id=user.item1_id,item2_id=user.item2_id,item3_id=user.item3_id,item4_id=user.item4_id).all()
            for otherUser in otherUsers:
                curUser=Users.query.filter_by(id=current_user.id).first()
                userr=Users.query.filter_by(id=otherUser.users_id).first()
                if userr.id != curUser.id:
                  postCount = Posts.query.filter_by(user_id=userr.id).count()
                  profile = Profile.query.filter_by(user_id=userr.id).first()
                  if profile:
                      im = Img.query.filter_by(id=profile.image_id).first()

                  user_data = {}
                  user_data['id'] = userr.id
                  user_data['username'] = userr.username
                  if profile:
                        user_data['user profile pic'] = im.img
                  user_data['num of posts'] = postCount
                  user_output.append(user_data)
                  random.shuffle(user_output)
    else:
        otherUsers = userInterests.query.all()
        for otherUser in otherUsers:
                curUser = Users.query.filter_by(id=current_user.id).first()
                userr = Users.query.filter_by(id=otherUser.users_id).first()
                if userr.id != curUser.id:
                    postCount = Posts.query.filter_by(user_id=userr.id).count()
                    profile = Profile.query.filter_by(user_id=userr.id).first()
                    if profile:
                        im = Img.query.filter_by(id=profile.image_id).first()

                    user_data = {}
                    user_data['id'] = userr.id
                    user_data['username'] = userr.username
                    if profile:
                        user_data['user profile pic'] = im.img
                    user_data['num of posts'] = postCount
                    user_output.append(user_data)
                    random.shuffle(user_output)


    posts = Posts.query.all()
    if not posts:
       return jsonify({'message': 'There is no posts yet in Discover Page'})
    post_output = []
    for post in posts:
        curUser = Users.query.filter_by(id=current_user.id).first()
        user=Users.query.filter_by(id=post.user_id).first()
        if user.id != curUser.id:
           imgg = Img.query.filter_by(id=post.image_id).first()
           profile = Profile.query.filter_by(user_id=user.id).first()
           if profile:
                im = Img.query.filter_by(id=profile.image_id).first()
           post_data = {}
           post_data['by'] = user.username
           if profile:
             post_data['user profile pic'] = im.img
           post_data['image_url'] = imgg.img
           post_data['desc'] = post.desc
           post_data['location'] = post.location
           post_data['date'] = post.date
           post_data['post_id'] = post.id
           post_output.append(post_data)
    random.shuffle(post_output)
    # if not user:
    #        return jsonify({'the list of users u interested in': 'it depends on your interests,please choose your interests', 'the list of posts': post_output})

    return jsonify({'the list of users u interested in': user_output, 'the list of posts': post_output})


    # -------------------------------BOOKMARKS------------------------------

@views.route('/AddToBookmarks/<id>', methods=['GET', 'POST'])
@token_required
def AddToBookmarks(current_user,id):
        if request.method == 'POST':
            post=Posts.query.filter_by(id=id).first()
            newBookmark = Bookmarks(user_id=current_user.id,post_id=post.id)
            db.session.add(newBookmark)
            db.session.commit()
            return jsonify({'message': 'new post is added to bookmarks'})


@views.route('/getMyBookmarks',methods=['POST', 'GET'])
@token_required
def getMyBookmarks(current_user):
    bookmarks = Bookmarks.query.filter_by(user_id=current_user.id).all()
    if not bookmarks:
       return jsonify({'message': 'There is no posts yet in Bookmarks .. Try to add post!'})
    output = []
    for bookmark in bookmarks:
        post = Posts.query.filter_by(id=bookmark.post_id).first()
        if not post:
            return jsonify({'message': 'There is no posts!'})
        user=Users.query.filter_by(id=post.user_id).first()
        profile = Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()
        imgg=Img.query.filter_by(id=post.image_id).first()
        bookmark_data = {}
        bookmark_data['by'] = user.username
        if profile:
            bookmark_data['user profile pic'] = im.img
        bookmark_data['image_url'] = imgg.img
        bookmark_data['desc'] = post.desc
        bookmark_data['location'] = post.location
        bookmark_data['date'] = post.date
        bookmark_data['post_id'] = post.id

        output.append(bookmark_data)
    return jsonify({'the list of posts': output})

@views.route('/removeBookmark/<post_id>', methods=['DELETE'])
@token_required
def removeBookmark(current_user, post_id):
        bookmark = Bookmarks.query.filter_by(user_id=current_user.id,post_id=post_id).first()
        if not bookmark:
            return jsonify({'message': 'bookmark does not exist'})
        db.session.delete(bookmark)
        db.session.commit()

        return jsonify({'message': 'Book mark is removed'})


     #------------------------------LIKES ON A POST--------------------------------

@views.route('/like/<id>/<action>',methods=['POST'])
@token_required
def like_action(current_user, id,action):
    post = Posts.query.filter_by(id=id).first()
    if action == 'like':
        current_user.like_post(post)
        db.session.commit()

        #THEN ADD TO NOTIFICATION
        new_notification = Notifications(receiver_user_id=post.user_id, sender_user_id=current_user.id,
                               notificationText=current_user.username + " has liked your post", read=False ,type="like")
        db.session.add(new_notification)
        db.session.commit()
        return jsonify({'message': 'Post is liked!'})

    if action == 'unlike':
        current_user.unlike_post(post)
        db.session.commit()
        return jsonify({'message': 'Post is unliked!'})

    return redirect(request.referrer)


@views.route('/like/<int:post_id>/viewLikers',methods=['GET'])
@token_required
def viewLikers(current_user,post_id):
    post = Posts.query.filter_by(id=post_id).first()
    print(post.get_likers())
    likers = []
    for liker in post.get_likers():
        user = Users.query.filter_by(id = liker.users_id).first()
        print(user.username)
        likers.append({
            'users_id': liker.users_id,
            'name': user.username,
            'post_id': liker.post_id
        })
    return jsonify({
        'Likers': likers
    })

    #----------------------------COMMENT ON A POST------------------------------


@views.route('/comment/<id>', methods=['POST'])
@token_required
def comment_action(current_user, id):
        # print(action)
        post = Posts.query.filter_by(id=id).first()
        # print(post.id)

        data = request.get_json()
        comment = PostComment(users_id=current_user.id, post_id=post.id,commentText=data['commentText'])
        db.session.add(comment)

        # THEN ADD TO NOTIFICATION

        user = Users.query.filter_by(id=current_user.id).first()
        print(user.username)
        new_notification = Notifications(receiver_user_id=post.user_id, sender_user_id=current_user.id,
                                             notificationText=user.username + " has commented your post", read=False,type= "comment")
        db.session.add(new_notification)
        db.session.commit()

        return jsonify({'message': user.username + ' has commented on this post!'})

        #return redirect(request.referrer)

@views.route('/comment/<int:post_id>/viewComments', methods=['GET'])
@token_required
def viewComments(current_user, post_id):
    post = Posts.query.filter_by(id=post_id).first()
    userr = Users.query.filter_by(id=post.user_id).first()
    profile = Profile.query.filter_by(user_id=userr.id).first()
    if profile:
        im = Img.query.filter_by(id=profile.image_id).first()
    print(post.get_comments())

    posterDesc = {}
    if profile:
         posterDesc['poster profile pic'] = im.img
    posterDesc['poster username'] = userr.username
    posterDesc['post desc'] = post.desc
    posterDesc['post date'] = post.date


    comments = PostComment.query.filter_by( post_id=post.id).all()
    if not comments :
        return jsonify({'poster': posterDesc, 'comments': 'there is no comments yet'})

    if post.get_comments:
        comments = []
        for comment in post.get_comments():
            user = Users.query.filter_by(id=comment.users_id).first()
            profile = Profile.query.filter_by(user_id=user.id).first()
            if profile:
                im = Img.query.filter_by(id=profile.image_id).first()
            if profile:
                comments.append({
                'users_id': comment.users_id,
                'user profile pic': im.img,
                'name': user.username,
                'comment': comment.commentText,
                'date': comment.date,
                'post_id': comment.post_id
                 })
            else:
                comments.append({
                    'users_id': comment.users_id,
                    'name': user.username,
                    'comment': comment.commentText,
                    'date': comment.date,
                    'post_id': comment.post_id
                })
        return jsonify({'poster': posterDesc, 'comments': comments})

@views.route('/comment/<comment_id>', methods=['DELETE'])
@token_required
def delete_comment(current_user, comment_id):
    postcomment = PostComment.query.filter_by(id=comment_id).first()
    db.session.delete(postcomment)
    db.session.commit()

    return jsonify({'message' : 'comment is deleted successfully'})


           #-----------------------------SHARE A POST------------------------------

@views.route('/post/<int:post_id>/getLink', methods=['GET'])
@token_required
def getShareLink(current_user, post_id):
    post = Posts.query.filter_by(id=post_id).first()
    if not post:
        return jsonify({'message': 'post does not exist'})
    new_sharing = SharePost(users_id=current_user.id,post_id=post.id)
    db.session.add(new_sharing)
    db.session.commit()

    return jsonify({'message': 'http://127.0.0.1:5001/post/'+str(post.id)})



   #------------------------------FOLLOWING AND FOLLOWERS--------------------------------

@views.route('/follow/<user_id>/<action>',methods=['POST'])
@token_required
def follow_action(current_user,user_id,action):
    user = Users.query.filter_by(id=user_id).first()
    if action == 'follow':
        if user is None:
            return jsonify({'message': 'user is not found!'})

        current_user.follow(user)
        db.session.commit()

        #THEN ADD TO NOTIFICATION

        userr = Users.query.filter_by(id=current_user.id).first()
        print(userr.username)
        new_notification = Notifications(receiver_user_id=user.id, sender_user_id=userr.id,
                               notificationText=userr.username + " has followed you!", read=False, type='follow')
        db.session.add(new_notification)
        db.session.commit()


        return jsonify({'message':  'you are now following ' + user.username })

    if action == 'unfollow':
        if user is None:
            return jsonify({'message': 'user is not found!'})
        current_user.unfollow(user)
        db.session.commit()
        return jsonify({'message': 'you unfollowed ' + user.username})

    return redirect(request.referrer)

@views.route('/viewMyFollowers',methods=['GET'])
@token_required
def viewMyFollowers(current_user):
    user = Users.query.filter_by(id=current_user.id).first()
    print(user.get_followers())
    followers = []
    for follower in user.get_followers():
        userr = Users.query.filter_by(id = follower.follower_id).first()
        print(userr.username)
        followers.append({
            'follower_id': follower.follower_id,
            'follower': userr.username,
            'followed_id': current_user.id
        })
    return jsonify({
        'Followers': followers
    })


    #------------------------------NOTIFICATIONS--------------------------------


@views.route('/get_all_notifications', methods=['GET'])
@token_required
def get_all_notifications(current_user):
    notifications = Notifications.query.filter_by(receiver_user_id=current_user.id).all()

    output = []
    for notification in notifications:
        user=Users.query.filter_by(id=notification.sender_user_id).first()
        print(user.username)
        print(notification)
        notification_data = {}
        notification_data['notification_id'] = notification.id
        notification_data['sender'] = user.username
        notification_data['notificationText'] = notification.notificationText
        notification_data['creation_date'] = notification.creation_date
        notification_data['read'] = notification.read
        notification_data['type'] = notification.type
        output.append(notification_data)
    if output:
        return jsonify({'notification' : output})
    else:
        return jsonify({'message' : 'No notifications yet'})


@views.route('/get_all_unread_notifications', methods=['GET'])
@token_required
def get_all_unread_notifications(current_user):
    notifications = Notifications.query.filter_by(receiver_user_id=current_user.id,read=False).all()

    output = []
    for notification in notifications:
        user=Users.query.filter_by(id=notification.sender_user_id).first()
        print(user.username)
        notification_data = {}
        notification_data['notification_id'] = notification.id
        notification_data['sender'] = user.username
        notification_data['notificationText'] = notification.notificationText
        notification_data['creation_date'] = notification.creation_date
        notification_data['read'] = notification.read
        notification_data['type'] = notification.type
        output.append(notification_data)
    if output:
        return jsonify({'notification' : output})
    else:
        return jsonify({'message' : 'No unread notifications yet'})

@views.route('/notification/<notification_id>', methods=['PUT','GET'])
@token_required
def read_one_notification(current_user, notification_id):
    notification = Notifications.query.filter_by(id=notification_id ,receiver_user_id=current_user.id).first()
    if not notification:
        return jsonify({'message' : 'notification was not found!'})
    user=Users.query.filter_by(id=notification.sender_user_id).first()
    print(user.username)
    post = PostLike.query.filter_by(users_id=notification.sender_user_id).first()
    notification_data = {}
    notification_data['sender'] =user.username
    notification_data['notificationText'] = notification.notificationText
    notification_data['notification_id'] = notification.id
    if notification.type != "follow":
       notification_data['postID'] = post.post_id
    notification_data['creation_date'] = notification.creation_date
    notification_data['read'] = True
    notification_data['type'] = notification.type
    notification.read = True
    db.session.commit()

    return jsonify({'notification' : notification_data})



@views.route('/notification/<notification_id>', methods=['DELETE'])
@token_required
def delete_notification(current_user, notification_id):
    notification = Notifications.query.filter_by(id=notification_id ,receiver_user_id=current_user.id).first()

    db.session.delete(notification)
    db.session.commit()

    return jsonify({'message' : 'notification is deleted successfully'})



     #------------------------------MESSAGES--------------------------------



@views.route('/get_all_messages', methods=['GET'])
@token_required
def get_all_messages(current_user):
    messages = Messages.query.filter_by(receiver_user_id=current_user.id).all()

    output = []
    for message in messages:
        user=Users.query.filter_by(id=message.sender_user_id).first()
        profile = Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()

        print(user.email)
        print(message)
        message_data = {}
        message_data['sender_user_id'] = message.sender_user_id
        message_data['sender'] = user.email
        if profile:
           message_data['sender_ProfilePic'] = im.img

        message_data['text'] = message.text
        message_data['creation_date'] = message.creation_date
        message_data['read'] = message.read
        output.append(message_data)
    if output:
        return jsonify({'message' : output})
    else:
        return jsonify({'message' : 'No messages'})

@views.route('/get_all_unread_messages', methods=['GET'])
@token_required
def get_all_unread_messages(current_user):
    messages = Messages.query.filter_by(receiver_user_id=current_user.id, read=False).all()

    output = []
    for message in messages:
        user = Users.query.filter_by(id=message.sender_user_id).first()
        profile = Profile.query.filter_by(user_id=user.id).first()
        if profile:
            im = Img.query.filter_by(id=profile.image_id).first()
        message_data = {}
        message_data['sender_user_id'] = message.sender_user_id
        message_data['sender'] = user.email
        if profile:
            message_data['sender_ProfilePic'] = im.img
        message_data['text'] = message.text
        message_data['creation_date'] = message.creation_date
        message_data['read'] = message.read
        output.append(message_data)
    if output:
        return jsonify({'message' : output})
    else:
        return jsonify({'message' : 'No unread messages'})

@views.route('/createMessage/<email>', methods=['POST'])
@token_required
def create_message(current_user,email):
    data = request.get_json()
    user = Users.query.filter_by(email=email).first()
    #  IN NEED OF INSERTING THE EMAIL OF THE ONE WHO I'LL SEND FOR HIM A MESSAGE


    #message = Messages.query.filter_by(sender_user_id=current_user.id,receiver_user_id=user.id).all()
    #user = Users.query.filter_by(id=message.receiver_user_id).first()
    #print(user.username)
    new_message = Messages(receiver_user_id=user.id,sender_user_id=current_user.id,text=data['text'], read=False)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message' : 'Email sent successfully'})


@views.route('/message/<message_id>', methods=['PUT'])
@token_required
def read_one_message(current_user, message_id):
    message = Messages.query.filter_by(id=message_id ,receiver_user_id=current_user.id).first()

    if not message:
        return jsonify({'message' : 'Email was not found!'})

    user=Users.query.filter_by(id=message.sender_user_id).first()
    profile = Profile.query.filter_by(user_id=user.id).first()
    if profile:
        im = Img.query.filter_by(id=profile.image_id).first()
    message_data = {}
    message_data['sender_user_id'] = message.sender_user_id
    message_data['sender'] = user.email
    if profile:
       message_data['sender_ProfilePic'] = im.img
    message_data['text'] = message.text
    message_data['creation_date'] = message.creation_date
    message_data['read'] = True
    message.read = True
    db.session.commit()

    return jsonify({'message' : message_data})

@views.route('/message/<message_id>', methods=['DELETE'])
@token_required
def delete_message(current_user, message_id):
    message = Messages.query.filter_by(id=message_id ,receiver_user_id=current_user.id).first()

    if not message:
        message = Messages.query.filter_by(id=message_id ,sender_user_id=current_user.id).first()

    if not message:
        return jsonify({'message' : 'Email was not found!'})

    db.session.delete(message)
    db.session.commit()

    return jsonify({'message' : 'message deleted successfully'})

    #----------------------------------APP SETTINGS--------------------------------

@views.route('/edit_appSettings', methods=['POST', 'PUT','GET'])
@token_required
def edit_appSettings(current_user):
            user = Users.query.filter_by(id=current_user.id).first()
            user_appSettings = AppSettings.query.filter_by(user_id=user.id).first()
            if user_appSettings:
                data = request.get_json()
                theme = data['theme']
                secure_email = data['secure_email']
                user_appSetting = AppSettings.query.filter_by(user_id=user.id).update(
                    dict( theme=theme,secure_email=secure_email))
                db.session.commit()
                appSettings_data = {}
                appSettings_data['theme'] = user_appSettings.theme
                appSettings_data['secure email'] = user_appSettings.secure_email
                return jsonify({'message': ' app settings is updated successfully','user appSettings_data': appSettings_data})

            else:
                default_appsettings = AppSettings(user_id=current_user.id, theme=0,secure_email='')
                db.session.add(default_appsettings)
                db.session.commit()
                appSettings_data = {}
                appSettings_data['theme'] = default_appsettings.theme
                appSettings_data['secure email'] = default_appsettings.secure_email
                return jsonify({'default appSettings Data': appSettings_data})

@views.route('/edit_accountSettings', methods=['POST', 'PUT','GET'])
@token_required
def edit_accountSettings(current_user):
            user = Users.query.filter_by(id=current_user.id).first()
            apperanceinfo=apperanceInfo.query.filter_by(users_id=user.id).first()
            user_accSettings = AccountSettings.query.filter_by(user_id=user.id).first()
            if user_accSettings:
                data = request.get_json()
                email = data['email']
                username = data['username']
                phoneNum = data['phoneNum']
                dateOfBirth = data['dateOfBirth']
                gender = data['gender']
                height = data['height']
                weight = data['weight']
                skintone = data['skintone']
                user_accSetting = AccountSettings.query.filter_by(user_id=user.id).update(
                    dict(email=email, username=username, phoneNum=phoneNum,
                         dateOfBirth=dateOfBirth,
                         gender=gender,height=height,weight=weight,skintone=skintone))

                updated_userInfo= Users.query.filter_by(id=user.id).update(
                    dict(email=email, username=username, phoneNum=phoneNum,
                         dateOfBirth=dateOfBirth,
                         gender=gender))

                updated_userAppearanceInfo = apperanceInfo.query.filter_by(id=user.id).update(
                    dict(height=height,weight=weight,skintone=skintone))

                db.session.commit()
                accSettings_data = {}
                accSettings_data['email'] =user_accSettings.email
                accSettings_data['username'] = user_accSettings.username
                accSettings_data['phoneNum'] = user_accSettings.phoneNum
                accSettings_data['date of birth'] = user_accSettings.dateOfBirth
                accSettings_data['gender'] = user_accSettings.gender
                accSettings_data['height'] = user_accSettings.height
                accSettings_data['weight'] = user_accSettings.weight
                accSettings_data['skintone'] = user_accSettings.skintone
                return jsonify({'message': ' account settings is updated successfully','user accSettings_data': accSettings_data})

            else:
                default_accsettings = AccountSettings(user_id=current_user.id, email=user.email, username=user.username, phoneNum=user.phoneNum,
                                                  dateOfBirth=user.dateOfBirth, gender=user.gender,height=apperanceinfo.height,weight=apperanceinfo.weight,skintone=apperanceinfo.skintone)
                db.session.add(default_accsettings)
                db.session.commit()
                accSettings_data = {}
                accSettings_data['email'] = default_accsettings.email
                accSettings_data['username'] = default_accsettings.username
                accSettings_data['phoneNum'] = default_accsettings.phoneNum
                accSettings_data['date of birth'] = default_accsettings.dateOfBirth
                accSettings_data['gender'] = default_accsettings.gender
                accSettings_data['height'] = default_accsettings.height
                accSettings_data['weight'] = default_accsettings.weight
                accSettings_data['skintone'] = default_accsettings.skintone

                return jsonify({'default accSettings Data': accSettings_data})


@views.route('/deleteAcc', methods=['DELETE'])
@token_required
def deleteAcc(current_user):
    user = Users.query.filter_by(id=current_user.id).first()
    if not user:
       return jsonify({'message': 'user does not exist'})
    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Account is deleted'})

@views.route('/changePassword', methods=['GET','POST'])
@token_required
def changePassword(current_user):

        data=request.get_json()
        current_password=data['current_password']
        # if not current_password:
        #     return make_response('password is wrong, please enter your current password!')
        user = Users.query.filter_by(id=current_user.id).first()
        if check_password_hash(user.password,current_password):
            return jsonify({'message': 'current password is correct'})
        else:
            return jsonify({'message': 'password is wrong, please re-enter your current password correctly!'})

@views.route('/createNewPassword', methods=['PUT', 'POST'])
@token_required
def createNewPassword(current_user):

        data = request.get_json()
        new_password = data['new_password']
        if len(new_password) < 6:
            return jsonify({'message': 'password is too short!'})
        user=Users.query.filter_by(id=current_user.id).update(
                        dict(password=generate_password_hash(new_password)))
        db.session.commit()
        return jsonify({'message': 'password is updated successfully!'})


         #------------------------------LOGOUT--------------------------------

@views.route('/logout')
@token_required
def logout(current_user):
    logout_user()
    return redirect(url_for('views.mainroute'))