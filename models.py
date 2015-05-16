from flask.ext.sqlalchemy import SQLAlchemy
from flask import Flask,current_app
from flask.ext.login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
app = Flask(__name__)
db = SQLAlchemy(app)


class Company(db.Model,UserMixin):
	__tablename__ = 'company'
	id = db.Column(db.Integer,primary_key=True)
	name = db.Column(db.String(128),unique=True)
	website = db.Column(db.String(128),unique=True)
	bounty = db.Column(db.Integer)
	email = db.Column(db.String(128),unique=True)
	confirmed = db.Column(db.Boolean,default=False)
	bugs_id = db.relationship('Bugs', backref='bugs', lazy='dynamic')


	def generate_confirmation_token(self, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'confirm': self.id})	

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def confirm(self,token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
			print "printing data"
			print data
		except:
			return False
		if data['confirm'] != self.id:
			print "data is not equal"
			print self.id
			print data
			return False
		self.confirmed = True
		db.session.add(self)
		print "sesion is added"
		return True


	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	def __repr__(self):
		return '<User %r>' % self.username





class Role(db.Model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)
	users = db.relationship('User', backref='role', lazy='dynamic')

	def __repr__(self):
		return '<Role %r>' % self.name


class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(64), unique=True, index=True)
	username = db.Column(db.String(64), unique=True, index=True)
	role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
	password_hash = db.Column(db.String(128))
	lined_in= db.Column(db.String(64))
	bugs_solved = db.Column(db.Integer,default=0)
	money_received = db.Column(db.Integer,default=0)
	confirmed = db.Column(db.Boolean, default=False)
	bugs = db.relationship('Bugs', backref='role', lazy='dynamic')


	def generate_confirmation_token(self, expiration=3600):
		s = Serializer(current_app.config['SECRET_KEY'], expiration)
		return s.dumps({'confirm': self.id})

	

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def confirm(self,token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
			print "printing data"
			print data
		except:
			return False
		if data['confirm'] != self.id:
			print "data is not equal"
			print self.id
			print data
			return False
		self.confirmed = True
		db.session.add(self)
		print "sesion is added"
		return True


	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	def __repr__(self):
		return '<User %r>' % self.username



class Bugs(db.Model):
	__tablename__ = 'bugs'
	id = db.Column(db.Integer,primary_key=True)
	type = db.Column(db.String(24))
	bounty = db.Column(db.Integer,default = 0)
	company_id = db.Column(db.Integer, db.ForeignKey('company.id')) 
	#this doesnt make into database as this is just a refernce
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	resolved = db.Column(db.Boolean,default=0)
	money_transfered = db.Column(db.Boolean,default=0)