from flask import session, redirect, url_for, escape,request, flash, current_app
from flask import render_template
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required, Email, length
from flaskext.mysql import MySQL
from flask import request
from flask.ext.script import Manager,Shell
from flask.ext.migrate import Migrate, MigrateCommand


from flask.ext.login import LoginManager, login_user, current_user, login_required

from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask.ext.sqlalchemy import SQLAlchemy
import os
from models import *

app.config['SECRET_KEY'] = "hacker one"

manager = Manager(app)


from flask.ext.mail import Message
app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[Flasky]'
app.config['FLASKY_MAIL_SENDER'] = 'Flasky Admin <flasky@example.com>'
def send_email(to, subject, template, **kwargs):
	msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
	sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
	msg.body = render_template(template + '.txt', **kwargs)
	msg.html = render_template(template + '.html', **kwargs)
	mail.send(msg)

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ksrinathchowdary9@gmail.com'		 # os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = 'gabbar9347'							#os.environ.get('MAIL_PASSWORD')
app.config['FLASKY_ADMIN'] = 'srinath'


from flask.ext.mail import Mail
mail = Mail(app)

app.config['SQLALCHEMY_DATABASE_URI'] ='mysql://root:srinath@localhost/hackerone'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'



db.create_all()

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

def make_shell_context():
	return dict(app=app, db=db, User=User, Role=Role)

manager.add_command("shell", Shell(make_context=make_shell_context))
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)



@app.route('/confirm/<token>')
@login_required
def confirm(token):
	if current_user.confirmed:
		print "from confirmed"
		return redirect(url_for('index'))
	if current_user.confirm(token):
		print "from confirming"
		# print current_user.confirmed(token)
		flash('You have confirmed your account. Thanks!')
	else:
		print "invalid token"
		flash('The confirmation link is invalid or has expired.')
	return redirect(url_for('index'))



# @app.before_app_request
def before_request():
	if current_user.is_authenticated() and not current_user.confirmed and request.endpoint[:5] != 'auth.':
		return redirect(url_for('unconfirmed'))

@app.route('/unconfirmed')
def unconfirmed():
	if current_user.is_anonymous() or current_user.confirmed:
		return redirect('main.index')
	return render_template('unconfirmed.html')


@app.route('/confirm')
@login_required
def resend_confirmation():

	user = User.query.filter_by(id=session['user_id']).first()
	token = current_user.generate_confirmation_token()
	send_email('confirm','Confirm Your Account','confirm',user=user, token=token)
	flash('A new confirmation email has been sent to you by email.')
	return "send a  msg"											#redirect(url_for('index'))


from threading import Thread
def send_async_email(app, msg):
	with app.app_context():
		mail.send(msg)

def send_email(to, subject, template, **kwargs):
	msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,sender=app.config['FLASKY_MAIL_SENDER'], recipients=[to])
	msg.body = render_template(template + '.txt', **kwargs)
	msg.html = render_template(template + '.html', **kwargs)
	thr = Thread(target=send_async_email, args=[app, msg])
	print msg
	thr.start()
	return thr

from flask.ext.login import logout_user, login_required
@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out.')
	return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		
		print 'session0'
		if session:
			logout_user()
		user = User.query.filter_by(email=request.form['email']).first()
		print user
		print 'session3'
		if user is not None and user.verify_password(request.form['password']):
			print "its not none"

			login_user(user)
			
			return redirect(request.args.get('next'))
		flash('Invalid username or password.')
		print "its none"
	return render_template('login.html')




# mysql = MySQL()
# conn = db.connect('localhost','root','srinath','hackerone')


# class User(UserMixin, db.Model):

#	 @property						 #stores the data from ddatabase
#	 def password(self):
#		 raise AttributeError('password is not a readable attribute')

#	 @password.setter
#	 def password(self, password):
#		 self.password_hash = generate_password_hash(password)

#	 def verify_password(self, password):
#		 return check_password_hash(self.password_hash, password)

#	 def __repr__(self):
#		 return '<User %r>' % self.username

#	 def generate_confirmation(self,expiration=3600):
#	 	s = Serializer(current_app.config['SECRET_KEY'],expiration)
#	 	return s.dumps({'confirm':self.id})

#	 def confirm(self,token):
#	 	s=Serializer(current_app['SECRET_KEY'])
#	 	try:
#	 		data = s.load(token)
#	 	except Exception, e:
#	 		return False
		
#	 	if data.get('confirm') != self.id :
#	 		return False

#	 	self.confirmed = True

def find_user(user):
	return User.query.filter_by(username=user).first()

def find_company(company):
	return Company.query.filter_by(name=company).first()

def find_bugs(bugs):
	return Bugs.query.filter_by(id = bugs)
		
@app.route('/auth',methods=['POST'])
def auth():
	print "asd"
	print "fdsd"
	print "jsngopf"
	print request.form['username']
	if request.method == 'POST':
		print "ok1"
		user = find_user(request.form['username'])
		print "okc"
		if user is None:
			print "ok2"
			user = User(username=request.form['username'])
			db.session.add(user)
			session['known'] = False
			if app.config['FLASKY_ADMIN']:
				try:
					send_email(app.config['FLASKY_ADMIN'], 'New User','mail/new_user', user=user)
				except:
					print "eror"
		else:
			session['known'] = True
		session['name'] = request.form['username']
		# request.form['username'] = ''
		return redirect(url_for('index'))



class RegistrationForm():

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')
	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already in use.')


@app.route('/register', methods=['GET', 'POST'])
def register():
	print "Sdfdsf"
	if request.method == 'POST':
		print "entered"
		print request.form['email']
		user = User(email=request.form['email'],username=request.form['username'],password=request.form['password'])
		db.session.add(user)
		print "session"
		
		db.session.commit()
		print "commitd"
		token = user.generate_confirmation_token()
		print token
		send_email(user.email, 'Confirm Your Account','confirm', user=user, token=token)
		flash('A confirmation email has been sent to you by email.')
		flash('You can now login.')
		return redirect(url_for('login')) 
	return render_template('registration.html')


class NameForm(Form):
	username = StringField("User Name", validators = [Required()])
	email = StringField("Email id", validators = [Email()])
	submit = SubmitField('Submit')


login_manager.init_app(app)
def create_app(config_name):
	login_manager.init_app(app)


@app.route('/')
def index():
	print "ok"
	
	return render_template('index.html')




# @app.route('/register')
# def registration():

# 	name = request.form['username']
# 	email = request.form['email']

# 	if request.method == 'POST':
# 		session['name'] = name
# 		# form.username.data = name
# 		# auth = Auth(name,email)
# 		# auth.validate_email()
# 		# auth.validate_name()
# 		# auth.insert_database()

# 		return redirect(url_for('Auth'))

# 	return render_template('registration.html',form = form, name = session.get('name'))



@app.route("/admin")
@login_required
def admin_roles():
	return "only for admin"


@app.route('/company',methods=['POST','GET'])
def company_register():
	if request.method == 'POST':
		name = request.form['name']
		company = find_company(name)
		if company is None:
			db.session.add(company)
			db.session.commit()
			token = user.generate_confirmation_token()
			send_email(company.email, 'Confirm Your Account','confirm', user=company, token=token)
			flash('A confirmation email has been sent to you by email.')
			flash('You can now login.')
			return redirect(url_for('company')) 
		else:
			return render_template("company_register.html")

	return render_template('company_register.html')

@app.route('/company/login',methods=['POST','GET'])
def company_login():
	if request.method == 'POST':
		name = request.form['name']
		company = find_company(name)
		email = request.form['email']
		if session:
			logout_user()
		
		if company is not None and company.verify_password(request.form['password']):
			print "its not none"

			login_user(company)
			
			return redirect(request.args.get('next') or url_for("index"))
		flash('Invalid username or password.')
		print "its none"

	return render_template('company_login.html')




@app.route('/bugs',methods = ['POST','GET'])
@login_required
def bugs():
	print "jjb"
	if request.method == 'POST':
		print "sdnd"
		print request
		type = request.form['type']
		company_name = request.form['company']

		
		company = find_company(company_name)
		print session

		print "\n\n\n printing comapny \n\n\n\n"
		print company
		bugs = Bugs(type = type,company_id = company.id,user_id = session['user_id'])
		db.session.add(bugs)
		return render_template("bugs_confirmed.html")
	return render_template('bugs.html')


from flask import jsonify, Response
import json

@app.route('/list',methods=['POST','GET'])
def list():
	# if request.method=='POST':
	user_id = 2 					#session['user_id']
	bugs= Bugs.query.filter_by(user_id = user_id).all()
	print "printing list \n\n\n"
	# print json.dumps(user)
	# print bugs
	# print bugs.type
	
	# a =[]
	# b=[]
	# data = {'type':a,'company_id':b}
	# results={}
	# c=[]
	# n = []

	# for x in bugs:
	# 	n.append({'type':x.type,'company_id':x.company_id})

	# print n
	# print "\n"
	# n = jsonify(n)
	# print n
	# print "\n"
	# f = {'records':n}
	# print jsonify(f)
	# return jsonify(data)
	# return jsonify(f)
	output = []
	for bug in bugs:
		row={}
		i=0
		# for field in Bugs.__table__.c:
		# 	x = str(field).split(".")[1]
		# 	row[x] = bugs.
		# 	i = i+1
		# 	print bugs[i]
		row['resolved']=bug.resolved
		row['money_transfered'] = bug.money_transfered
		row['user_id'] = bug.user_id
		row['company_id'] = bug.user_id
		row['type'] = bug.type
		row['bounty'] = bug.bounty
		row['id'] = bug.id
		print "\n printing rows"
		print row

		output.append(row)

	print type(output)
	print "\n outing data"
	print output

	print jsonify(data =output)
	print "\n json dummping \n\n"
	z = json.dumps(output)
	data = {'records':output}
	print type(data)
	return jsonify(data)
	# return jsonify(records=output)






















if __name__ == '__main__':
	# manager.run()
	app.run(debug = True)