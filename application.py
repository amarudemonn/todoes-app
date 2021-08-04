import os

from flask import Flask, render_template, redirect, request, flash, url_for, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

from helpers import starts_with_number, contains_numbers, doesnt_have_symbols, get_current_date, login_required

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///data.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.urandom(32)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    tasks = db.relationship("Task", backref="user", lazy='dynamic')

    def __repr__(self):
        return f"<User {self.username}>"


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_todo = db.Column(db.Text, nullable=False)
    date = db.Column(db.Text, nullable=False)
    is_completed = db.Column(db.Integer, nullable=False, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<Task {self.id}>"


db.Index("username_idx", User.username)
db.Index("username_id_idx", Task.user_id)
db.Index("is_completed_idx", Task.is_completed)
db.Index("task_id_idx", Task.id)


@app.before_first_request
def create_tables():
    db.create_all()


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        task = request.form.get("task")

        if not task:
            flash("Task is required", category="error")
            return redirect(url_for("index"))

        if len(task) < 2:
            flash(
                "Your task should be at least 2 characters long(like the word be)", category="error")
            return redirect(url_for("index"))

        if starts_with_number(task):
            flash("Your task should not start with numbers", category="error")
            return redirect(url_for("index"))

        if task.startswith(" ") or task.endswith(" "):
            flash(
                "Your task should not start with spaces or end with spaces", category="error")
            return redirect(url_for("index"))

        if not task[0].isalpha():
            flash("Your task should not start with symbols", category="error")
            return redirect(url_for("index"))

        tasks = Task.query.filter_by(user_id=session["user_id"]).with_entities(
            Task.task_todo, Task.is_completed).all()

        for taskname in tasks:
            if "".join(taskname[0].strip().lower().split(" ")) == "".join(task.strip().lower().split(" ")) and taskname[1] == 0:
                flash("Task already exists", category="error")
                return redirect(url_for("index"))

        user = User.query.get(session["user_id"])

        new_task = Task(
            task_todo=task.strip().title(),
            date=get_current_date(),
            is_completed=0,
            user=user
        )
        db.session.add(new_task)
        db.session.commit()

        return redirect(url_for("index"))

    current_tasks = Task.query.filter_by(
        user_id=session["user_id"],
        is_completed=0
    ).with_entities(
        Task.id,
        Task.task_todo,
        Task.date,
        Task.is_completed
    ).all()

    completed_tasks = Task.query.filter_by(
        user_id=session["user_id"],
        is_completed=1
    ).with_entities(
        Task.id,
        Task.task_todo,
        Task.date,
        Task.is_completed
    ).all()

    user = User.query.get(session["user_id"])

    return render_template("index.html",
                           user=user,
                           current_tasks=current_tasks,
                           completed_tasks=completed_tasks,
                           current_tasks_total=len(current_tasks),
                           completed_tasks_total=len(completed_tasks)
                           )


@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":

        session.clear()

        username = request.form.get("username")

        if not username:
            flash("Username is required", category='error')
            return redirect(url_for("login"))

        users = User.query.with_entities(User.username).all()

        is_exist = False
        for user in users:
            if user[0] == username:
                is_exist = True
                break

        if is_exist == False:
            flash("User doesn't exist", category='error')
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()

        password = request.form.get("password")

        if not password:
            flash("password is required", category='error')
            return redirect(url_for("login"))

        if not check_password_hash(user.password, password):
            flash("Wrong password", category='error')
            return redirect(url_for("login"))

        session["user_id"] = user.id

        flash("Successfully logged in")

        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username")

        if not username:
            flash("Username is required.", category="error")
            return redirect(url_for("register"))

        if len(username) < 6:
            flash("Username should be at least 6 characters long.", category="error")
            return redirect(url_for("register"))

        if not doesnt_have_symbols(username):
            flash("Username should not have any symbols and spaces", category="error")
            return redirect(url_for("register"))

        if starts_with_number(username):
            flash("Username should not start with numbers.", category="error")
            return redirect(url_for("register"))

        users = User.query.with_entities(User.username).all()

        for user in users:
            if user[0] == username:
                flash("Username already exists", category='error')
                return redirect(url_for("register"))

        password = request.form.get("password")

        if not password:
            flash("Password is required.", category="error")
            return redirect(url_for("register"))

        if len(password) < 10:
            flash("Password should be at least 10 characters long.", category="error")
            return redirect(url_for("register"))

        if " " in password:
            flash("Password should not contain spaces", category="error")
            return redirect(url_for("register"))

        if not contains_numbers(password):
            flash("Password should contain at least 1 number.", category="error")
            return redirect(url_for("register"))

        if password.islower():
            flash(
                "Password should contain at least 1 upper case character.", category="error")
            return redirect(url_for("register"))

        password_confirm = request.form.get("password-confirm")

        if password != password_confirm:
            flash("Passwords don't match.", category="error")
            return redirect(url_for("register"))

        new_user = User(username=username, password=generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        ))
        db.session.add(new_user)
        db.session.commit()

        flash("Success. Please Log In.")

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/action/<action_type>/<task_id>")
@login_required
def action(action_type, task_id):
    if not action_type:
        flask("You should provide action type", category="error")
        return redirect(url_for("index"))

    if action_type not in ["update", "delete"]:
        flash("Wrong action type")
        return redirect(url_for("index"))

    if not task_id:
        flask("You should provide task id", category="error")
        return redirect(url_for("index"))

    task = Task.query.filter_by(id=task_id).first()

    if not task:
        flash("Wrong task id", category="error")
        return redirect(url_for("index"))

    if task.user_id != session["user_id"]:
        flash("Access denied", category="error")
        return redirect(url_for("index"))

    if action_type == "update":
        task.is_completed = 1
        db.session.commit()
    elif action_type == "delete":
        db.session.delete(task)
        db.session.commit()

    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():

    session.clear()

    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run()
