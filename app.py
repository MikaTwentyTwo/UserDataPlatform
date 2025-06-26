
from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime
import pandas as pd
import logging
import io

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = "super-secret-key"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

logging.basicConfig(filename='audit.log', level=logging.INFO)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    role = db.Column(db.String(50))
    email = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        admin = Admin.query.filter_by(username=request.form['username']).first()
        if admin and bcrypt.check_password_hash(admin.password, request.form['password']):
            login_user(admin)
            return redirect(url_for('index'))
        else:
            flash("Неверный логин или пароль", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    q = request.args.get("q")
    users = User.query.filter(User.name.contains(q)).all() if q else User.query.all()
    return render_template('index.html', users=users)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        name, role, email = request.form['name'], request.form['role'], request.form['email']
        db.session.add(User(name=name, role=role, email=email))
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_user.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.name, user.role, user.email = request.form['name'], request.form['role'], request.form['email']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit_user.html', user=user)

@app.route('/delete/<int:id>')
@login_required
def delete_user(id):
    db.session.delete(User.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/export')
@login_required
def export_excel():
    users = User.query.all()
    df = pd.DataFrame([{
        "ID": u.id, "Имя": u.name, "Роль": u.role, "Email": u.email, "Дата создания": u.created_at.strftime("%Y-%m-%d %H:%M")
    } for u in users])
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name="Пользователи")
    output.seek(0)
    return send_file(output, download_name="users.xlsx", as_attachment=True)

@app.route('/create-admin')
def create_admin():
    if Admin.query.first():
        return "Администратор уже создан"
    admin = Admin(username="admin", password=bcrypt.generate_password_hash("admin").decode('utf-8'))
    db.session.add(admin)
    db.session.commit()
    return "Администратор создан: admin/admin"

if __name__ == "__main__":
    app.run(debug=True)
