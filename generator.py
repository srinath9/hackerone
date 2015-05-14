from flask import Flask, session, redirect, url_for, escape,request, flash
from flask import render_template
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required, Email, length
from flaskext.mysql import MySQL
from flask import request
import MySQLdb as db
from flask.ext.login import LoginManager, login_user
from flask.ext.login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer


login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'


mysql = MySQL()
conn = db.connect('localhost','root','srinath','hackerone')


class User(UserMixin, db.Model):

    @property                         #stores the data from ddatabase
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username

    def generate_confirmation(self,expiration=3600):
    	s = Serializer(current_app.config['SECRET_KEY'],expiration)
    	return s.dumps({'confirm':self.id})

    def confirm(self,token):
    	s=Serializer(current_app['SECRET_KEY'])
    	try:
    		data = s.load(token)
    	except Exception, e:
    		return False
    	
    	if data.get('confirm') != self.id :
    		return False

    	self.confirmed = True
    	





class NameForm(Form):
	username = StringField("User Name", validators = [Required()])
	email = StringField("Email id", validators = [Email()])
	submit = SubmitField('Submit')




app = Flask(__name__)
app.config['SECRET_KEY'] = "hacker one"


@app.route('/')
def index():
	return render_template("index.html")


class Auth(name=None,email=None):
	
	def validate_email():
		query = "SELECT * FROM user_details WHERE email_id =%s" 

		cursor = conn.cursor()
		if cursor.execute(query,(email)):
			flash("email already exist")
			return redirect(url_for("registration"))

		return True

	def validate_name():
		query = "SELECT * FROM user_details WHERE user_name =%s" 
		cursor = conn.cursor()
		if cursor.execute(query,(name)):
			flash("name already taken")
			return redirect(url_for("registration"))

		return True

	def login_user_check():
		query = "SELECT * FROM user_details WHERE user_name =%s AND email_id = %s" 
		cursor = conn.cursor()
		if cursor.execute(query,(name,email)):
			details = cursor.fetchone()
			return details
			



	def insert_database():
		cursor =conn.cursor()
		query = "INSERT INTO user_details (email_id,autherized,user_name,bugs_solved,money_recived,linkedin_link) VALUES (%s,1,%s,2,9,'rat')"
		cursor.execute(query,(email,name))
		conn.commit()
		flash("you are sucessfully registered")

		return redirect(url_for("login"))

	
	




@app.route('/login', methods=['POST','GET'])
def  login():
	if request.method == 'POST':
		
		name = request.form['username']
		email = request.form['email']

		details = Auth(name,email)
		if details is not None :
			login_user(details)
			session['name'] = name
			return redirect(url_for('index'))

		flask("incorrect deatils")
		conn.commit()
		
		return redirect(url_for('login'))
		
		
	
	return render_template("login.html")
	
@app.route("/logout")
def logout():
	session.pop('username', None)
	return redirect(url_for('index'))


@app.route('/register')
def registration():

	name = request.form['username']
	email = request.form['email']

	if form.validate_on_submit():
		session['name'] = form.username.data
		form.username.data = name
		auth = Auth(name,email)
		auth.validate_email()
		auth.validate_name()
		auth.insert_database()

		return redirect(url_for('Auth'))

	return render_template('registration.html',form = form, name = session.get('name'))

@login_required.user_loader
def user_load(userid):
	query = "SELECT * FROM user_details WHERE id = %s "
	cursor = conn.cursor()
	cursor.execute(query,(userid))
	details = cursor.fetchone()
	conn.commit()
	
	return details



@app.route("/admin")
@login_required
def admin_roles():
	return "only for admin"

















if __name__ == '__main__':
	app.run(debug=True)