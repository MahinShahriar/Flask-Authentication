from flask import Flask , render_template , request, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import EmailField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, InputRequired, Length, ValidationError
import json

#from flask_bcrypt import bcrypt   -- Having an error for device limitation 
#while trying to install bcrypt
#

# ALTERNATIVE OF bcrypt
def hash_string(text):
    # Hash the input string
    hashed_text = ""
    for char in text:
        hashed_char = chr(ord(char) + 1)  # Shift each character by 1
        hashed_text += hashed_char
    return hashed_text

with open('config.json', 'r') as j:
  para = json.load(j)['para']

app = Flask(__name__ , static_folder="static", template_folder='template')
app.config['SECRET_KEY'] = "XYZ333@mail_net"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

local_server = False
if (local_server):
  app.config['SQLALCHEMY_DATABASE_URI'] = para["local_db_uri"]
else:
  app.config['SQLALCHEMY_DATABASE_URI'] = para["prod_db_uri"]

db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view ='login'


@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))


class SignUpForm(FlaskForm):
  username  = StringField(validators=[
              DataRequired(),Length(min=2,max=40)],render_kw={'placeholder':'Full Username'})
  
  email     = EmailField('Email', validators=[
              DataRequired(), Email()],render_kw={'placeholder':'Email'})
  
  password  = PasswordField(validators=[
              DataRequired(),Length(min=4,max=20)],render_kw={'placeholder':'Password'})
  
  re_password  = PasswordField(validators=[
              DataRequired(),Length(min=4,max=20)],render_kw={'placeholder':'Confirm Password'})
  
  submit    = SubmitField('Sign up')
  
  def validate_email(self,email):
    existing_email = User.query.filter_by(email=email.data).first()
    if existing_email:
      raise ValidationError('Already have an account with following email address, Please Login or enter another.')


class SignInForm(FlaskForm):
  email    = EmailField('Email', validators=[
             DataRequired(), Email()], render_kw={'placeholder':'Email'})
  
  password = PasswordField(validators=[
             InputRequired(), Length(min=4,max=20)], render_kw={'placeholder':'Password'})
  
  submit   = SubmitField('Sign in')  


@app.route('/')
def home():
  return render_template('home.html')


@app.route('/signin',methods=['GET','POST'])
def signin():
  form = SignInForm()
  if form.validate_on_submit():
    user = User.query.filter_by(email=form.email.data).first()
    if user:
      if user.password== hash_string(form.password.data):
        login_user(user)
        return redirect('/dashboard')
      else: 
        messages = flash('Password not mathced ! please try again.')
    else:
      messages = flash('Email not found ! please try again.')
  
  return render_template('signin.html', form=form)


@app.route('/signup', methods=['GET','POST'])
def sign_up():
  form = SignUpForm()
  if form.validate_on_submit() and (form.password.data == form.re_password.data):
    password = form.password.data
    hash_pass = hash_string(password)
    new_user = User(username=form.username.data,email=form.email.data, password=hash_pass)
    db.session.add(new_user)
    db.session.commit()
    return redirect('signin')
  return render_template('signup.html', form=form)

@app.route('/dashboard', methods=["GET","POST"])
@login_required
def dashboard():
  user = current_user
  return render_template('dashboard.html',user=user)

@app.route('/logout')  
@login_required
def logout():
  return redirect('signin')

#=========== RUN SECTION ===========
if __name__ == '__main__':
  with app.app_context():
        db.create_all()
  app.run(debug= True) 