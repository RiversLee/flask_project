#unicoding=utf-8
from werkzeug.security import generate_password_hash,check_password_hash
from . import db
from flask_login import UserMixin,AnonymousUserMixin
from . import login_manager
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from datetime import datetime
from faker import Faker
import hashlib
from random import randint
from sqlalchemy.exc import IntegrityError
from flask import request
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(64),unique=True)
    users = db.relationship('User',backref='role',lazy='dynamic')
    default = db.Column(db.Boolean,default=False,index=True)
    permissions = db.Column(db.Integer)
    def __repr__(self):
        return '<Role %r>'%self.name
    def __int__(self,**kwargs):
        super(Role,self).__int__(**kwargs)
        if self.permissions is None:
            self.permissions = 0
    @staticmethod
    def insert_roles():
        roles = {
            'User':(Permission.FOLLOW |
                    Permission.COMMENT|
                    Permission.WRITE_ARTICLES,True),
            'Moderator':(Permission.FOLLOW|
                         Permission.COMMENT|
                         Permission.WRITE_ARTICLES|
                         Permission.MODERATE_COMMENTS,False),
            'Administrator':(0xff,False)

        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name = r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def has_permission(self,perm):
        return self.permissions & perm == perm

    def add_permission(self,perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self,perm):
        if self.has_permission(perm):
            self.permissions -= perm
    def reset_permissions(self):
        self.permissions = 0

class User(UserMixin,db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(64),unique=True,index=True)
    username = db.Column(db.String(64),unique=True,index=True)
    confirmed = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer,db.ForeignKey('roles.id'))
    posts = db.relationship('Post',backref='author',lazy='dynamic')

    name = db.Column(db.String(64)) #真实姓名
    location = db.Column(db.String(64)) #所在地
    about_me = db.Column(db.Text()) #自我介绍 db.Test()最大的好处这个不需要指定最大长度
    member_since = db.Column(db.DateTime(),default=datetime.utcnow) #注册日期
    last_seen = db.Column(db.DateTime(),default=datetime.utcnow)  #最后访问时间
    avatar_hash = db.Column(db.String(32))
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    def __init__(self,**kwargs):
        super(User,self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
                if self.role is None:
                    self.role = Role.query.filter_by(default=True)
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()
    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    def __repr__(self):
        return '<Users %r>'%self.username

    @staticmethod
    def users(count=100):
        fake = Faker("zh_CN")
        i = 0
        while i < count:
            u = User(email=fake.email(),
                     username=fake.user_name(),
                     password='password',
                     confirmed=True,
                     name=fake.name(),
                     location=fake.city(),
                     about_me=fake.text(),
                     member_since=fake.past_date())
            db.session.add(u)
            try:
                db.session.commit()
                i += 1
            except IntegrityError:
                db.session.rollback()

    def generate_confirmation_token(self,expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'],expiration)

        return s.dumps({'confirm.txt':self.id})
    def confirm(self,token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:

            data = s.loads(token)
        except:
            return False
        if data.get('confirm.txt') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        db.session.commit()
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id}).decode('utf-8')

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps(
            {'change_email': self.id, 'new_email': new_email}).decode('utf-8')

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        db.session.add(self)
        return True
    def can(self,permissions):
        return self.role is not None and (self.role.permissions & permissions) ==  permissions
    def is_administrator(self):
        return self.can(Permission.ADMIN)
    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def gravatar(self,size=100,default='identicon',rating='g'):
        url = 'https://secure.gravatar.com/avatar'

        hash = self.avatar_hash or self.gravatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

class AnonymousUser(AnonymousUserMixin):
    def can(self,permissions):
        return False
    def is_administrator(self):
        return False
        login_manager.anonymous_user = AnonymousUser

#操作权限
class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMIN = 0x80

class Post(db.Model):
    __tablename__= 'posts'
    id = db.Column(db.Integer,primary_key=True)
    body = db.Column(db.Text)
    timetamp = db.Column(db.DateTime,index=True,default=datetime.utcnow)
    author_id = db.Column(db.Integer,db.ForeignKey('users.id'))

    @staticmethod
    def posts(count=100):
        fake = Faker("zh_CN")
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=fake.text(),
                     timetamp=fake.past_date(),
                     author=u)
            db.session.add(p)
        db.session.commit()


class LakerMessage(db.Model):
    __tablename__ = 'laker'
    id = db.Column(db.Integer, primary_key=True)
    tile = db.Column(db.Text)
    context = db.Column(db.Text)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
