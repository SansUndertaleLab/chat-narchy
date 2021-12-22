from flask import *
from flask_sqlalchemy import *
from flask_login import LoginManager, UserMixin, login_user, login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
app=Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///database.db"
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
app.config["SECRET_KEY"]="whatareyoudoinghere"

login_manager=LoginManager(app)
login_manager.init_app(app)
login_manager.login_view="login"
class User(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),nullable=False,unique=True)
    password=db.Column(db.String(20),nullable=False)
    def __repr__(self):
        return '<User %r>' % self.username
class Message(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    userid=db.Column(db.Integer,nullable=False)
    message=db.Column(db.String(100),nullable=False)
    username=db.Column(db.String(20),nullable=False)
    date_created=db.Column(db.DateTime,default=datetime.utcnow)
    def __repr__(self):
        return '<Message %r>' % self.id
class RegisterForm(FlaskForm):
    username=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password=PasswordField(validators=[InputRequired(),Length(min=8,max=20)],render_kw={"placeholder":"Password"})
    submit=SubmitField("Register")

    def validate_username(self,username):
        existing_username=User.query.filter_by(username=username.data).first()
        if existing_username:
            raise ValidationError("That username already exists, please use another one.")

class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Username"})
    password=PasswordField(validators=[InputRequired(),Length(min=8,max=20)],render_kw={"placeholder":"Password"})
    submit=SubmitField("Login")

class PostForm(FlaskForm):
    message=StringField(validators=[InputRequired(),Length(min=1,max=100)],render_kw={"placeholder":"Message"})
    submit=SubmitField("post")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    return render_template("home.html")
@app.route("/register",methods=["GET","POST"])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user=User(username=form.username.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return render_template("register.html",form=form)
@app.route("/login",methods=["GET","POST"])
def login():
    form=LoginForm()
    if form.validate_on_submit:
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect("/dashboard")
    return render_template("login.html",form=form)
@app.route("/dashboard",methods=["GET","POST"])
@login_required
def dashboard():
    form=PostForm()
    post=Message.query.order_by(Message.date_created).all()
    if form.validate_on_submit and request.method=="POST":
        new_post=Message(userid=current_user.id,message=form.message.data,username=current_user.username)
        db.session.add(new_post)
        db.session.commit()
        return redirect("/dashboard")
    return render_template("dashboard.html",form=form,posts=post)
@app.route("/logout",methods=["GET","POST"])
@login_required
def logout():
    logout_user()
    return redirect("/")
@app.route("/delete/account/<int:id>")
@login_required
def delete(id):
    if id==current_user.id:
        logout_user()
        delete_user=User.query.get_or_404(id)
        db.session.delete(delete_user)
        db.session.commit()
    else:
        return redirect("/warning/account")
    return redirect("/")
@app.route("/delete/message/<int:id>")
@login_required
def delete_message(id):
    message_to_delete=Message.query.get_or_404(id)
    if message_to_delete.userid==current_user.id:
        db.session.delete(message_to_delete)
        db.session.commit()
    else:
        return redirect("/warning/message")
    return redirect("/dashboard")
@app.route("/warning/account")
def warnAcc():
    logout_user()
    return render_template("warningAcc.html")
@app.route("/warning/message")
def warnMsg():
    logout_user()
    return render_template("warningMsg.html")
@app.route("/edit/<int:id>",methods=["GET","POST"])
def edit_msg(id):
    msg=Message.query.get_or_404(id)
    if request.method=="POST":
        msg.message=request.form["content"]
        db.session.commit()
        return redirect("/dashboard")
    else:
        if msg.userid==current_user.id:
            return render_template("update.html",post=msg)
        else:
            return redirect("/warning/edit")
@app.route("/warning/edit")
def warnEdit():
    logout_user()
    return render_template("warningEdit.html")
if __name__=="__main__":
    app.run(debug=True)