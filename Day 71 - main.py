from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import md5
from typing import List
import os
from day_71_forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)

admin = False
 
def gravatar_url(email, size=100, rating='g', default='retro', force_default=False):
    hash_value = md5(email.lower().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_value}?s={size}&d={default}&r={rating}&f={force_default}"

# TODO: Configure Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///day-71-posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

def admin_only(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if admin:
            return func(*args, **kwargs)
        else:
            return abort(403)
    return inner


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("User", back_populates='posts')
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments: Mapped[List["Comment"]] = relationship(back_populates='parent_post')
    author_id = db.Column(Integer, ForeignKey('users.id'))

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    comments: Mapped[List["Comment"]] = relationship(back_populates="author")
    posts: Mapped[List["BlogPost"]] = relationship(back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author = relationship("User", back_populates='comments')
    author_id = db.Column(Integer, ForeignKey('users.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(Integer, ForeignKey("blog_posts.id"))
    comment: Mapped[str] = mapped_column(String, nullable=False)

with app.app_context():
    db.create_all()

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        hashed_password = generate_password_hash(request.form.get('password'), 'pbkdf2:sha256', salt_length=10)
        new_user = User(
            email = request.form.get('email'),
            password = hashed_password,
            name = request.form.get('name')
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except:
            flash("You have already signed up with that email, log in instead.")
            return redirect(url_for('login'))
        
        login_user(new_user)
        print(new_user.id)
        if new_user.id == 1:
            global admin
            admin = True
            print("ADMIN LOGGED")
        return redirect(url_for('get_all_posts'))
    return render_template("Day 71 - register.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    global admin
    form = LoginForm()
    if request.method == "POST":
        user = db.session.execute(db.select(User).where(User.email == request.form.get('email'))).scalar()
        if not user:
            flash('Email does not exist, please try again')
            return redirect(url_for('login'))
        else:
            if check_password_hash(user.password, request.form.get('password')):
                login_user(user)
                print(user.id)
                if user.id == 1:
                    print("ADMIN LOGGED")
                    admin = True
                    print(admin)
                else:
                    admin = False
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password is incorrect, please try again.')
                return redirect(url_for('login'))
    return render_template("Day 71 - login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    global admin
    admin = False
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    print("printed")
    return render_template("Day 71 - index.html", logged_in=current_user.is_authenticated, admin=admin, all_posts=posts)
    # return render_template('test.html')


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    print(admin)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
            author=current_user,
            parent_post=requested_post,
            comment=comment_form.comment_text.data

            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("You need to log in to comment.")
            return redirect(url_for('login'))
    return render_template("Day 71 - post.html", post=requested_post, logged_in=current_user.is_authenticated, admin=admin, form=comment_form, gravatar_url=gravatar_url)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("Day 71 - make-post.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("Day 71 - make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("Day 71 - about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("Day 71 - contact.html", logged_in=current_user.is_authenticated)