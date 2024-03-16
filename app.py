from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from functools import wraps
from flask import abort
from datetime import datetime

class UploadForm(FlaskForm):
    file = StringField('File', validators=[InputRequired()])
    year = SelectField('Year', choices=[(str(year), str(year)) for year in range(datetime.now().year-10, datetime.now().year+1)], validators=[InputRequired()])
    month = SelectField('Month', choices=[('01', 'January'), ('02', 'February'), ('03', 'March'), ('04', 'April'),
                                          ('05', 'May'), ('06', 'June'), ('07', 'July'), ('08', 'August'),
                                          ('09', 'September'), ('10', 'October'), ('11', 'November'), ('12', 'December')],
                         validators=[InputRequired()])
    submit = SubmitField('Upload')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/uploads/<path:filename>')
@login_required
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)  

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    year = db.Column(db.String(4), nullable=False)
    month = db.Column(db.String(2), nullable=False)  
    user = db.relationship('User', backref=db.backref('files', lazy=True))
    def get_url(self):
        return url_for('serve_file', filename=self.filepath[len(app.config['UPLOAD_FOLDER'])+1:], _external=True)

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    username = request.args.get('username', '')
    year = request.args.get('year', '')
    month = request.args.get('month', '')
    group_by = request.args.get('group_by', '')

    query = File.query.join(User)
    if username:
        query = query.filter(User.username.like(f"%{username}%"))
    if year:
        query = query.filter(File.year == year)
    if month:
        query = query.filter(File.month == month)

    files = query.all()

    grouped_files = {}
    if group_by == 'year':
        for file in files:
            key = file.upload_date.strftime('%Y')
            if key not in grouped_files:
                grouped_files[key] = []
            grouped_files[key].append(file)
    elif group_by == 'month':
        for file in files:
            key = file.upload_date.strftime('%Y-%m')
            if key not in grouped_files:
                grouped_files[key] = []
            grouped_files[key].append(file)
    else:
        grouped_files['all'] = files 

    return render_template('admin_panel.html', grouped_files=grouped_files, group_by=group_by, current_year=datetime.now().year)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(), 
        EqualTo('password', message='Passwords must match.')
    ])
    first_name = StringField('First Name', validators=[InputRequired()])
    last_name = StringField('Last Name', validators=[InputRequired()])
    submit = SubmitField('Register')

@app.route('/')
@login_required
def profile():
    user_details = {
        'first_name': current_user.first_name,
        'last_name': current_user.last_name
    }
    return render_template('index.html', user=user_details)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=True)
                return redirect(url_for('index'))
            else:
                flash('Incorrect Password!', 'login')
        else:
            flash('Username is not exist!', 'login')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            username=form.username.data, 
            password=hashed_password,
            first_name=form.first_name.data, 
            last_name=form.last_name.data   
        )
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Registration successful!', 'register')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'register')
    return render_template('register.html', form=form)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        file = request.files['file']
        if file and file.filename.endswith('.pdf'):
            filename = secure_filename(file.filename)
            year = form.year.data
            month = form.month.data
            user_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, year, month)
            if not os.path.exists(user_path):
                os.makedirs(user_path)
            file_path = os.path.join(user_path, filename)
            file.save(file_path)

        new_file = File(
            filename=filename,
            filepath=file_path,
            user_id=current_user.id,
            year=form.year.data,
            month=form.month.data 
        )
        db.session.add(new_file)
        db.session.commit()

        flash('File successfully uploaded', 'upload') 
        return redirect(url_for('upload_file'))
    return render_template('upload.html', form=form)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
