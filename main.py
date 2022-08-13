import flask
import werkzeug
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import Table, Column, Integer, ForeignKey
import hashlib

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")
# db.create_all()

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

    post_id = Column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

db.create_all()





# db.create_all()
# ADMIN = User.query.get(1)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    # admin = User.query.get(1)
    user_is_admin = User.query.get(1) == current_user
    return render_template("index.html", all_posts=posts, user_is_admin=user_is_admin,logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "GET":
        return render_template("register.html", form=form)
    elif request.method == "POST":
        if form.validate_on_submit():
            if User.query.filter_by(email=request.form["email"]).first() is None:
                new_user = User(
                    name=form.name.data,
                    email=form.email.data,
                    password=werkzeug.security.generate_password_hash(password=form.password.data, method='pbkdf2:sha256',
                                                                      salt_length=8)
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("An account with that email already exists; please sign-in instead.", 'error')
                return redirect(url_for('login'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user != User.query.get(1) and not current_user.is_anonymous: #the user is not the admin and is not anonymous
            print("Admin is current user: ")
            print(User.query.get(1) is current_user)
            print(f"ADMIN: {User.query.get(1).name}")
            print(f"Current User: {current_user.name}")
            abort(403)
        elif current_user.is_anonymous:
            abort(404)
        return function(*args, **kwargs)



    return decorated_function


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "GET":
        return render_template("login.html", form=form)
    elif request.method == "POST":
        users = db.session.query(User).all()
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user is not None:
            if check_password_hash(pwhash=user.password, password=request.form["password"]):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password Incorrect, please try again.", 'error')
                return render_template("login.html", form=form)
        else:
            flash('Email does not exist, please try again.', 'error')
            return render_template("login.html", form=form)
            # return redirect(url_for('get_all_posts'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    user_is_admin = User.query.get(1) == current_user
    if request.method == "GET":
        # admin = User.query.get(1)
        comments = Comment.query.all()
        return render_template("post.html", post=requested_post, user_is_admin=user_is_admin, form=form, logged_in=current_user.is_authenticated, comments=comments)
    elif request.method == "POST":
        if current_user.is_authenticated:
            if form.validate_on_submit():
                new_comment = Comment(
                    author_id=current_user.id,
                    text=form.comment.data,
                    post_id=post_id
                )
                db.session.add(new_comment)
                db.session.commit()
                comments = Comment.query.all()
            return render_template("post.html", comments=comments, post=requested_post, user_is_admin=user_is_admin, form=form, logged_in=current_user.is_authenticated)
        else:
            flash('Please Login or Register to comment.', 'error')
            return redirect(url_for("login"))




@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == "GET":
        return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)
    elif request.method == "POST":
        if form.validate_on_submit():
            new_post = BlogPost(
                author_id=current_user.id,
                author=current_user,
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                date=date.today().strftime("%B %d, %Y"),

            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
