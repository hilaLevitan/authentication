from flask import Flask, render_template,request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
login_manager = LoginManager()
app = Flask(__name__)
secrete_key=os.environ.get("SECRETE_KEY")
app.config['SECRET_KEY'] = secrete_key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)
##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# db.create_all()
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



@app.route('/')
def home():
    return render_template("index.html",logged_in=current_user.is_authenticated)


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        user=User.query.filter_by(email=request.form.get('email')).first()
        if user is not None:
            flash('You are already registered, please log in')
            return redirect(url_for("login"))
        user=User(email=request.form['email'],password=generate_password_hash(password=request.form['password'],method='pbkdf2:sha256',salt_length=8),name=request.form['name'])
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("secrets"))
    return render_template("register.html",logged_in=current_user.is_authenticated)


@app.route('/downloadi')
def downloadi():

    return send_from_directory('static','files/cheat_sheet.pdf')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        user=User.query.filter_by(email=request.form.get('email')).first()
        if user is None:
            flash('The email does not exist, please try again')
        else:
            is_correct_password=check_password_hash(user.password,request.form['password'])
            print(is_correct_password)
            if is_correct_password:
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('secrets'))
            flash('password incorrect, please try again')
        
    return render_template("login.html",logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html",name=current_user.name,logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('index.html',logged_in=current_user.is_authenticated)


@app.route('/download')
def download():
    pass


if __name__ == "__main__":
    app.run(debug=True)
