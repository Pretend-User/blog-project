from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateUserForm, LogIn, Comment
from flask_gravatar import Gravatar
from functools import wraps
from smtplib import SMTP
import os
from dotenv import load_dotenv


load_dotenv("C:\Testing\Sensitive Data\.env")


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


EMAIL = os.getenv("EMAIL")
PASSWORD = os.getenv("PASSWORD")


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("APP_SEC_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100), nullable=False)
    email = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("Users", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments", back_populates="parent_post")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("Users", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                    )


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        if Users.query.filter_by(email=form.email.data).first():
            flash("Email already registered. Try Logging In")
            return redirect(url_for("login"))
        password = generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=8)
        user = Users(
            user=form.username.data,
            email=form.email.data,
            password=password,
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LogIn()
    if form.validate_on_submit():
        email = form.email.data
        user = Users.query.filter_by(email=email).first()
        if user is None:
            flash("Invalid Email, please try again")
        else:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect password, please try again")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = Comment()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Please Login to comment")
            return redirect(url_for("login"))
        comment = Comments(
            user_id=current_user.id,
            comment=form.comment.data,
            post_id=post_id
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/contact', methods=['POST', 'GET'])
def contact():
    if request.method == "POST":
        name = request.form['text']
        email = request.form['email']
        phone = request.form['phone']
        msg = request.form['msg']
        with SMTP('smtp.gmail.com') as connection:
            connection.starttls()
            connection.login(user=EMAIL, password=PASSWORD)
            connection.sendmail(from_addr=EMAIL,
                                to_addrs=EMAIL,
                                msg=f"Subject:Client Contact\n\n"
                                    f"Name: {name}\n"
                                    f"Email: {email}\n"
                                    f"Phone: {phone}\n"
                                    f"Message: {msg}"
                                )
        return render_template("contact.html", msg_sent=True)
    return render_template("contact.html", msg_sent=False)


@app.route("/new-post", methods=["POST", "GET"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
