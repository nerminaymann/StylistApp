from flask_sqlalchemy import SQLAlchemy
from . import db
from flask_login import UserMixin
from datetime import datetime
import json
from time import time
from flask import request

class Followers (db.Model):
    __tablename__ = 'followers'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Users(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer ,primary_key=True,autoincrement=True,nullable=False )
    public_id = db.Column(db.Integer)
    email= db.Column(db.String(50),unique=True,nullable=False)
    password = db.Column(db.String(50),unique=True,nullable=False)
    ID_device = db.Column(db.String(100), unique=True, nullable=True)
    uuID = db.Column(db.String(100), unique=True, nullable=True)
    userType = db.Column(db.String(50), unique=True, nullable=False)
    #image_id = db.Column(db.Integer, db.ForeignKey('img.id'))
    post = db.relationship('Posts', backref='author', lazy='dynamic')

    username = db.Column(db.String(80), nullable=False)
    gender = db.Column(db.Integer, nullable=False)
    phoneNum = db.Column(db.String(50), unique=True)
    dateOfBirth = db.Column(db.String(20))

#,default=datetime.strftime("%b %d %y")

    liked = db.relationship(
        'PostLike',
        foreign_keys='PostLike.users_id',
        backref='user', lazy='dynamic')

    followed = db.relationship('Followers',
                               foreign_keys=[Followers.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Followers',
                                foreign_keys=[Followers.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')


    commented = db.relationship(
        'PostComment',
        foreign_keys='PostComment.users_id',
        backref='user', lazy='dynamic')

    voted = db.relationship(
        'Voting',
        foreign_keys='Voting.users_id',
        backref='user', lazy='dynamic')

    def has_liked_post(self, post):
        return PostLike.query.filter(
            PostLike.users_id == self.id,
            PostLike.post_id == post.id).count() > 0

    def like_post(self, post):
        if not self.has_liked_post(post):
            like = PostLike(users_id=self.id, post_id=post.id)
            db.session.add(like)

    def unlike_post(self, post):
        if self.has_liked_post(post):
            PostLike.query.filter_by(
                users_id=self.id,
                post_id=post.id).delete()

    def is_following(self, user):
        return Followers.query.filter(
            Followers.follower_id == self.id,
            Followers.followed_id == user.id).count() > 0


    def follow(self, user):
        if not self.is_following(user):
            follow = Followers(follower_id=self.id, followed_id=user.id)
            db.session.add(follow)

    def unfollow(self, user):
        if self.is_following(user):
            Followers.query.filter_by(
                follower_id=self.id,
                followed_id=user.id).delete()

    def get_followers(self):
        followers = Followers.query.filter_by(follower_id=Users.id, followed_id=self.id).all()
        return followers



class Profile(db.Model):
    tablename = 'profile'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image_id = db.Column(db.Integer, db.ForeignKey('img.id'))
    bio = db.Column(db.String(100), nullable=True)
    fb_link = db.Column(db.String(100), nullable=True)
    ig_link = db.Column(db.String(100), nullable=True)
    pinterest_link = db.Column(db.String(100), nullable=True)


class apperanceInfo(db.Model):
    __tablename__ = 'apperanceinfo'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    height = db.Column(db.String(50))
    weight = db.Column(db.String(50))
    skintone = db.Column(db.String(50))
    shoe_size = db.Column(db.String(50))
    shirt_size = db.Column(db.String(50))
    pant_size = db.Column(db.String(50))
    skirt_size = db.Column(db.String(50))
    dress_size = db.Column(db.String(50))


class fullInterests(db.Model):
    __tablename__ = 'fullinterests'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    item = db.Column(db.String(50), nullable=False)
    image_id = db.Column(db.Integer, db.ForeignKey('img.id'))



class userInterests(db.Model):
    __tablename__ = 'userinterests'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    item1_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'),nullable=False)
    item2_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'),nullable=False)
    item3_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'),nullable=False)
    item4_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item5_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item6_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item7_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item8_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item9_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item10_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item11_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item12_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
    item13_id = db.Column(db.Integer, db.ForeignKey('fullinterests.id'), nullable=True)
#
#
class fullEvents(db.Model):
    __tablename__ = 'fullevents'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    item = db.Column(db.String(50), nullable=False)
    image_id = db.Column(db.Integer, db.ForeignKey('img.id'))


class userEvents(db.Model):
    __tablename__ = 'userevents'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    item1_id = db.Column(db.Integer, db.ForeignKey('fullevents.id'), nullable=False)
    item2_id = db.Column(db.Integer, db.ForeignKey('fullevents.id'), nullable=False)
    item3_id = db.Column(db.Integer, db.ForeignKey('fullevents.id'), nullable=False)
    item4_id = db.Column(db.Integer, db.ForeignKey('fullevents.id'), nullable=True)
    item5_id = db.Column(db.Integer, db.ForeignKey('fullevents.id'), nullable=True)
    item6_id = db.Column(db.Integer, db.ForeignKey('fullevents.id'), nullable=True)
    item7_id = db.Column(db.Integer, db.ForeignKey('fullevents.id'), nullable=True)
    item8_id = db.Column(db.Integer, db.ForeignKey('fullevents.id'), nullable=True)


class fullAesthetics(db.Model):
    __tablename__ = 'fullaesthetic'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    item = db.Column(db.String(50), nullable=False)
    image_id = db.Column(db.Integer, db.ForeignKey('img.id'))


class userAesthetics(db.Model):
    __tablename__ = 'useraesthetic'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    item1_id = db.Column(db.Integer, db.ForeignKey('fullaesthetic.id'), nullable=False)
    item2_id = db.Column(db.Integer, db.ForeignKey('fullaesthetic.id'), nullable=False)
    item3_id = db.Column(db.Integer, db.ForeignKey('fullaesthetic.id'), nullable=False)
    item4_id = db.Column(db.Integer, db.ForeignKey('fullaesthetic.id'), nullable=True)
    item5_id = db.Column(db.Integer, db.ForeignKey('fullaesthetic.id'), nullable=True)
    item6_id = db.Column(db.Integer, db.ForeignKey('fullaesthetic.id'), nullable=True)
    item7_id = db.Column(db.Integer, db.ForeignKey('fullaesthetic.id'), nullable=True)
    item8_id = db.Column(db.Integer, db.ForeignKey('fullaesthetic.id'), nullable=True)


class PostLike(db.Model):
    __tablename__ = 'PostLike'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))


class PostComment(db.Model):
    __tablename__ = 'PostComment'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    commentText = db.Column(db.String(100))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    date = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)

class SharePost(db.Model):
    __tablename__ = 'sharepost'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))

class Img(db.Model):
    __tablename__ = 'img'
    id = db.Column(db.Integer,primary_key=True,autoincrement=True)
    img = db.Column(db.String(200),nullable=False)
    name = db.Column(db.Text, nullable=False)
    mimetype = db.Column(db.Text, nullable=False)
    imageType = db.Column(db.String(50))


class Posts(db.Model):
    __tablename__ = 'post'
    id= db.Column(db.Integer, primary_key=True,autoincrement=True )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image_id = db.Column(db.Integer, db.ForeignKey('img.id'))
    desc=db.Column(db.String(200))
    location=db.Column(db.String(200))
    date=db.Column(db.DateTime(timezone=True),default=datetime.utcnow)
    likes = db.relationship('PostLike', backref='post', lazy='dynamic')

    def get_likers(self):
        likers = PostLike.query.filter_by(users_id=Users.id, post_id=self.id).all()
        return likers

    def get_comments(self):
        comments = PostComment.query.filter_by(users_id=Users.id, post_id=self.id).all()
        return comments

class Bookmarks(db.Model):
    __tablename__ = 'bookmarks'
    id= db.Column(db.Integer, primary_key=True,autoincrement=True )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))

class Stars(db.Model):
    __tablename__ = 'stars'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    star = db.Column(db.String(50), nullable=False)

class Ratings(db.Model):
    __tablename__ = 'ratings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    star1_id = db.Column(db.Integer, db.ForeignKey('stars.id'))
    star2_id = db.Column(db.Integer, db.ForeignKey('stars.id'))
    star3_id = db.Column(db.Integer, db.ForeignKey('stars.id'))
    star4_id = db.Column(db.Integer, db.ForeignKey('stars.id'))
    star5_id = db.Column(db.Integer, db.ForeignKey('stars.id'))
    tip_id = db.Column(db.Integer, db.ForeignKey('tip.id'))

class Tips(db.Model):
    __tablename__ = 'tip'
    id= db.Column(db.Integer, primary_key=True,autoincrement=True )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image_id = db.Column(db.Integer, db.ForeignKey('img.id'))
    caption=db.Column(db.String(100))
    date=db.Column(db.DateTime(timezone=True),default=datetime.utcnow)
    #ratings = db.relationship('PostLike', backref='post', lazy='dynamic')

class Polls(db.Model):
    __tablename__ = 'poll'
    id= db.Column(db.Integer, primary_key=True,autoincrement=True )
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image1_id = db.Column(db.Integer, db.ForeignKey('img.id'))
    image2_id = db.Column(db.Integer, db.ForeignKey('img.id'))
    caption=db.Column(db.String(100))
    creation_date = db.Column(db.DateTime, default=datetime.now())

    def get_votes(self):
        votes = Voting.query.filter_by(users_id=Users.id, poll_id=self.id).all()
        return votes

class Voting(db.Model):
    __tablename__ = 'voting'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    users_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    poll_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    image_id = db.Column(db.Integer, db.ForeignKey('img.id'))


class Notifications(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    receiver_user_id = db.Column(db.String(50))
    sender_user_id = db.Column(db.String(50))
    notificationText = db.Column(db.String(100))
    creation_date = db.Column(db.DateTime, default=datetime.now())
    read = db.Column(db.Boolean)
    type = db.Column(db.String(50))


class Messages(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    receiver_user_id = db.Column(db.String(50))
    sender_user_id = db.Column(db.String(50))
    text = db.Column(db.String(500))
    creation_date = db.Column(db.DateTime, default=datetime.now())
    read = db.Column(db.Boolean)



class AppSettings(db.Model):
    __tablename__ = 'appsettings'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'))
    theme = db.Column(db.Integer,nullable=False)
    secure_email=db.Column(db.String(50),nullable=True)

class AccountSettings(db.Model):
    __tablename__ = 'accsettings'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'))
    email = db.Column(db.String(50),nullable=False)
    username = db.Column(db.String(80),nullable=False)
    phoneNum = db.Column(db.String(50), nullable=False)
    dateOfBirth=db.Column(db.String(20),nullable=False)
    gender=db.Column(db.Integer,nullable=False)
    height=db.Column(db.String(50), nullable=True)
    weight=db.Column(db.String(50), nullable=True)
    skintone=db.Column(db.String(50),nullable=True)


