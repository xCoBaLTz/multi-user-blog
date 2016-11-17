import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

secret = 'thisisverysecret'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

#def render_post(response, post):
#    response.out.write('<b>' + post.subject + '</b><br>')
#    response.out.write(post.content)


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def user_key(group="default"):
    return db.Key.from_path('users', name)

def post_key(post_id):
    return db.Key.from_path('Post', int(post_id), parent=blog_key())

def like_dup(ent, login_id, post_id):
    key = post_key(post_id)
    like_exists = db.GqlQuery("SELECT * "
                              "FROM " + ent +
                              " WHERE like_user_id = '" + login_id +
                              "' AND ANCESTOR IS :1", key).get()
    return like_exists


class Post(db.Model):
    author_id = db.StringProperty(required=True)
    author_name = db.StringProperty(required=True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def post_likes(self, post_id):
        kinds = metadata.get_kinds()
        if u'PostLike' in kinds:
            likes = db.GqlQuery("SELECT * FROM PostLike WHERE ANCESTOR IS :1", post_key(post_id)).count()
        else:
            likes = 0
        return likes

    def render(self, login_id, post_id):
        likes = self.post_likes(post_id)
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self, login_id = login_id, likes = likes)

    def post_like_dup(self, login_id, post_id):
        exists = like_dup('PostLike', login_id, post_id)
        return exists

class PostLike(db.Model):
    like_user_id = db.StringProperty(required=True)

class Comment(db.Model):
    author_id = db.StringProperty(required = True)
    author_name = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DataTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self, login_id):
        self._render_body = self.body.replace('\n', '<br>')
        return render_str("post.html", login_id=login_id, c = self)

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

    def post(self):
        if not self.user:
            self.redirect('/signup')
        else:
            edit_post_id = self.request.get('edit_post_id')
            comment_post_id = self.request.get('comment_post_id')
            like_post_id = self.request.get('like_post_id')
            if comment_post_id:
                post_id = comment_post_id
                self.redirect('/newcomment?post_id=' + post_id)
            if edit_post_id:
                post_id = edit_post_id
                self.redirect('/editpost?post_id=' + post_id)
            if like_post_id:
                post_id = like_post_id
                user_id = self.read_secure_cookie('usercookie')
                if not like_dup('PostLike', user_id, post_id):
                    like = PostLike(like_user_id=user_id,
                                    parent=post_key(post_id))
                    like.put()
                    self.redirect('/')

class PostPage(BlogHandler):
    def get(self, login_id):
        url_str = self.request.path
        post_id = url_str.rsplit('post-', 1)[1]
        key = post_key(post_id)
        post = db.get(key)

        kinds = metadata.get_kinds()

        if u'Comment' in kinds:
            comments = db.GqlQuery("SELECT * FROM Comment WHERE ANCESTOR IS :1", key)
        else:
            comments=""
        self.render("permalink.html", post=post, comments=comments)

    def post(self, login_id):
        if not self.user:
            self.redirect('/login')
        else:
            edit_post_id = self.reqeust.get('get_post_id')
            edit_comment_id = self.request.get('get_post_id')
            comment_post_id = self.request.get('comment_post_id')
            like_post_id = self.request.get('like_post_id')
            if commment_post_id:
                post_id = comment_post_id
                self.redirect('/newcomment?post_id=' + post_id)
            if edit_post_id:
                post_id = edit_post_id
                self.redirect('/editpost?post_id=' + post_id)
            if edit_comment_id:
                url_str = self.request.path
                post_id = url_str.rsplit('post-', 1)[1]
                comment_id = edit_comment_id
                self.redirect('/editcomment?post_id=%s&comment_id=%s' % (post_id, comment_id))
            if like_post_id:
                post_id = like_post_id
                user_id = self.read_secure_cookie('user_id')
                if not like_dup('PostLike', user_id, post_id):
                    like = PostLike(like_user_id=user_id, parent=post_key(post_id))
                    like.put()
                    self.redirect('/post-%s' % post_id)

class CommentPage(BlogHandler):
        

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')
        created_by = str(self.user.key().id())
        subject = self.request.get('subject')
        content = self.request.get('content')
        key = db.Key.from_path('User', int(created_by), parent=user_key())
        user = db.get(key)
        if subject and content and created_by:
            p = Post(parent = blog_key(), subject = subject, content = content,
                    author_name = user.name, created_by = created_by)
            p.put()
            post_id = str(p.key().id())
            self.redirect('/post-%s' % post_id)
        else:
            error = "Subject and Content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)

class NewComment(BlogHandler):
    def get(self):
        if not self.user:
            self.redirect('/login')
        else:
            post_id = self.request.get('post_id')
            self.render("newcomment.html", post_id=post_id)

    def post(self):
        if not self.user:
            self.redirect('/login')
        post_id = self.request.get('post_id')
        created_by = str(self.user.key().id())
        content = self.request.get('content')
        key = db.Key.from_path('User', int(created_by), parent=user_key())
        user = db.get(key)
        if subject and content and created_by:
            c = Comment(parent = post_key(post_id), subject = subject, content = content,
                    author_name = user.name, created_by = created_by)
            c.put()
            comment_id = str(c.key().id())
            self.redirect('/comment-%s?post_id=%s' % (comment_id, post_id))
        else:
            error = "Content, please!"
            self.render("newcomment.html", content=content, post_id=post_id,
                        error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/post-([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/comment-([0-9]+)',CommentPost),
                               ('/newcomment', NewComment),
                               ('/deletepost', DeletePost),
                               ('/deletecomment', DeleteComment),
                               ('/editpost', EditPost),
                               ('/editcomment', EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome)
                               ],
                              debug=True)
