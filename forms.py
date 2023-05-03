from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class CreateUserForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired("Field cannot be empty")])
    username = StringField("Username", validators=[DataRequired("Field cannot be empty")])
    password = PasswordField("Password", validators=[DataRequired("Field cannot be empty")])
    submit = SubmitField("Sign Me Up")


class LogIn(FlaskForm):
    email = EmailField("Email", validators=[DataRequired("Field cannot be empty")])
    password = PasswordField("Password", validators=[DataRequired("Field cannot be empty")])
    submit = SubmitField("Log In")


class Comment(FlaskForm):
    comment = CKEditorField("Your Comment:", validators=[DataRequired()])
    submit = SubmitField("Submit")
