from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
#from werkzeug.security import generate_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://admin:123@localhost/itdata'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking, unless you need it

Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))
    #is_admin = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    @staticmethod
    def create_admin(username, email, password):
        hashed_password = generate_password_hash(password, method='sha256')
        admin = User(username=username, email=email, password=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        return admin

@login_manager.user_loader
def load_user(user_id):
    print(user_id)
    return db.session.query(User).get(int(user_id))




def create_tables():
    with app.app_context():
        db.create_all()

create_tables()






class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4,max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4,max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))

        return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)









@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return "<h1>New user has been created!</h1>"

    return render_template('signup.html', form=form)







@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))












# Define your route for admin-only access
@app.route('/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)  # Forbidden error
    # If user is an admin, render the admin dashboard template
    return render_template('dashboard.html')

@app.route('/index')
@login_required
def user():
    #if not current_user.is_admin:
        #abort(403)  # Forbidden error
    # If user is an admin, render the admin dashboard template
    return render_template('index.html')


# First, make sure you've imported the necessary modules and set up your Flask app and database

# Then, call the create_admin method with the desired admin credentials





if __name__ == '__main__':
    with app.app_context():
        """admin_username = 'admin1'
        admin_email = 'admin@exampl.com'
        admin_password = 'admin'  # You should set a secure password here

# Call create_admin method to create the admin user
        admin_user = User.create_admin(admin_username, admin_email, admin_password)

# Optionally, print or use the created admin user
        print("Admin user created:", admin_user.username)"""
        #create_tables()
    app.run(debug=True)