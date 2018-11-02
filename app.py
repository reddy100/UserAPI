from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session, jsonify
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from forms import LoginForm, RegisterForm, GetForm, SetForm
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
db = SQLAlchemy(app)

bootstrap = Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/abishek/Code/HaloAPI/database.db'
app.config['SECRET_KEY'] = '09134832084uriehfdsh!'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class UserTable(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(15), unique=True)
	email = db.Column(db.String(50), unique=True)
	password = db.Column(db.String(80))
	stuff = db.relationship('KeyValueTable', backref='user', uselist=False)


class KeyValueTable(db.Model):
	__tablename__ = 'keyValues'
	id = db.Column(db.Integer, primary_key=True)
	key = db.Column(db.String(50))
	value = db.Column(db.String(50))
	user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))


@login_manager.user_loader
def load_user(user_id):
    return UserTable.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error=None
    if form.validate_on_submit():
    	if form.username.data and form.password.data:
	        user = UserTable.query.filter_by(username=form.username.data).first()
	        if user:
	            if check_password_hash(user.password, form.password.data):
	                login_user(user, remember=form.remember.data)
	                return render_template('profile.html', name=user.username)
	        error='Invalid username or password'
    return render_template('login.html', form=form, error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
    	if form.email.data and form.username.data and form.password.data:
	        hashed_password = generate_password_hash(form.password.data, method='sha256')
	        new_user = UserTable(username=form.username.data, email=form.email.data, password=hashed_password)
	        db.session.add(new_user)
	        db.session.commit()
	        flash('You have successfully signed up')
	        return render_template('index.html')

    return render_template('signup.html', form=form)

'''
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    form1 = GetForm()
    form2 = SetForm()
    return render_template('profile.html', form1=form1, form2=form2)

'''

@app.route('/get', methods = ['GET', 'POST'])
@login_required
def get():
	form = GetForm()
	error=None
	if form.validate_on_submit():
		if form.key.data:
			stuffTable = current_user.stuff
			if stuffTable:
				key = stuffTable.query.filter_by(key=form.key.data).first()
				if key:
					flash('This keys value is: '+key.value)
				else:
					error= 'This key does not exist'
			else:
				error='Youve put nothing in to take out'
	return render_template('get.html', form=form, error=error)

@app.route('/set', methods = ['GET', 'POST'])
@login_required
def set():
	form = SetForm()

	if form.validate_on_submit():
		if form.key.data and form.value.data:
			new_stuff = KeyValueTable(key=form.key.data, value=form.value.data, user_id=current_user.id)
			db.session.add(new_stuff)
			db.session.commit()
			flash('Successfully added key and value')
	return render_template('set.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8088)