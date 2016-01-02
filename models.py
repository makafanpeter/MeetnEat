from sqlalchemy import Column,ForeignKey,Integer,String, Boolean, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
import datetime


Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
    #Add a method to generate auth tokens here

    def generate_auth_token(self, expiration=600):
    	s = Serializer(secret_key, expires_in = expiration)
    	return s.dumps({'id': self.id })

    #Add a method to verify auth tokens here
    @staticmethod
    def verify_auth_token(token):
    	s = Serializer(secret_key)
    	try:
    		data = s.loads(token)
    	except SignatureExpired:
    		#Valid Token, but expired
    		return None
    	except BadSignature:
    		#Invalid Token
    		return None
    	user_id = data['id']
    	return user_id

    @property
    def serialize(self):
         """Return object data in easily serializeable format"""
         return {
            "id" : self.id,
            "username": self.username,
            "picture" : self.picture
            }



class OAuthMembership(Base):
    """docstring for """
    __tablename__ = 'oauthmembership'
    provider = Column(String(30), primary_key=True)
    provider_userid =  Column(String(100), primary_key=True)
    user_id =  Column(Integer,ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
         """Return object data in easily serializeable format"""
         return {
         "provider" : self.provider,
         "provideruserid": self.provider_userid
         }



class Request(Base):
    """docstring forRequest"""
    __tablename__ = 'request'
    id = Column(Integer, primary_key = True)
    filled = Column(Boolean, default= False)
    meal_time = Column(DateTime)
    longitude = Column(Float)
    latitude = Column(Float)
    location_string =(String(100))
    meal_type = Column(String(100))
    user_id =  Column(Integer,ForeignKey('user.id'))
    user = relationship(User)


    @property
    def serialize(self):
         """Return object data in easily serializeable format"""
         return {
         "id" : self.id,
         "filled": self.filled,
         "meal_type": self.meal_type,
         "longitude": self.longitude,
         "latitude": self.latitude,
         "location_string": self.location_string,
         "meal_type": self.meal_type,
         }


class Proposal(Base):
    """docstring forProposal"""
    __tablename__ = 'proposal'
    id = Column(Integer, primary_key = True)
    filled = Column(Boolean, default= False)
    request_id =  Column(Integer,ForeignKey('request.id'))
    user_proposed_to = Column(Integer)
    user_proposed_from = Column(Integer)
    request = relationship(Request)


    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        "id" : self.id,
        "filled": self.filled,
        "request_id": self.request_id,
        "user_proposed_to": self.user_proposed_to,
        "user_proposed_from": self.user_proposed_from,
        }


class MealDate(Base):
    __tablename__ = "mealdate"
    id = Column(Integer, primary_key = True)
    meal_time = Column(DateTime)
    restaurant_picture = Column(String(100))
    restaurant_address = Column(String(120))
    restaurant_name =  Column(String(100))
    user_1 =  Column(Integer)
    user_2 = Column(Integer)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
        "id" : self.id,
        "meal_time": self.meal_time,
        "restaurant_picture": self.restaurant_picture,
        "restaurant_address": self.restaurant_address,
        "restaurant_name": self.restaurant_name,
        "user_1": self.user_1,
        "user_2": self.user_2
        }





engine = create_engine('sqlite:///meatneat.db')


Base.metadata.create_all(engine)
