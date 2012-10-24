#!/usr/bin/env python
# -*- coding: utf-8 -*-

import webapp2
import cgi
import string
import os
import jinja2
import re
import datetime
from google.appengine.ext import db
import hashlib
import blogcrypt

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(autoescape = True,
	loader = jinja2.FileSystemLoader(template_dir))

def rot13(text):
	out = ''
	offset = 13
	aval = ord('a')	
	Aval = ord('A')
	alp_range = ord('z') - ord('a') + 1
 
	for char in text:
		char_num = ord(char)
		if (char_num >= ord('a')) and (char_num <= ord('z')):
			new_char = ((char_num - aval + offset) % alp_range) + aval
			new_char = chr(new_char)
			out += new_char
		elif (char_num >= ord('A')) and (char_num <= ord('Z')):
			new_char = ((char_num - Aval + offset) % alp_range) + Aval
			new_char = chr(new_char)
			out += new_char
		else:
			out += char
	return out


class BaseHandler(webapp2.RequestHandler):
	def render(self,template, **kw):
		self.response.out.write(render_str(template,**kw))
	def write(self,*a,**kw):
		self.response.out(*a,**kw)

class Rot13(BaseHandler):
	def get(self):
		self.render('rot13.html')
	def post(self):
		text = self.request.get('text')
		enc_text = rot13(text)
		self.render('rot13.html',text =enc_text)


# ############################################################################
# BLOG STUFF HERE ------------------------------------------------------------
# ############################################################################


def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def blog_key(name = 'default'):
	return db.Key.from_path('blogs',name)

class BlogHandler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)
	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)
	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

class Signup(BlogHandler):
	def get(self):
		self.render('signup.html')
	def post(self):
		username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		password_re = re.compile(r"^.{3,20}$")
		email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

		username = self.request.get('username') 
		password = self.request.get('password') 
		verify = self.request.get('verify') 
		email = self.request.get('email')

		has_error = False
		fields = {}
		fields['username'] = username
		fields['email']  = email

		if username_re.search(username) is None:
			has_error = True
			fields['username_error'] = "That's not a valid username" 
		if password_re.match(password) is None:
			has_error = True
			fields['password_error'] = "That wasn't a valid password"
		if password != verify:
			has_error = True
			fields['verify_error'] = "Your passwords do not match"
		if email and (email_re.match(email) is None):
			has_error = True
			fields['email_error'] = 'Bad e-mail entered'
		if has_error:
			self.render('signup.html', **fields)
		else:
			user  = User(username = username, password_hash = blogcrypt.make_pw_hash(username,password), email = email)
			user.put() #stores user
			self.redirect('/blog/welcome?username='+username)


class Welcome(BaseHandler):
	def get(self):
		username = self.request.get('username')
		self.render('welcome.html',username = username)

class Submit(BlogHandler):
	def get(self):
		self.render('submit.html')
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			blog_post = Entry(subject=subject, content=content)
			blog_post.put() #stores the blog post
			blog_id = blog_post.key().id()
			self.redirect('/blog/%s' % blog_id)
		else:
			error = "You need both a subject and content to be filled out"
			self.render('submit.html',subject=subject,content=content, error= error)

class FrontPage(BlogHandler):#
	def get(self):
		entries =  db.GqlQuery("SELECT * FROM Entry ORDER BY date_created DESC LIMIT 10")
		self.render("frontpage.html",entries=entries)

class Permalink(BlogHandler):
	def get(self, blog_id):
		key = db.Key.from_path('Entry',int(blog_id))
		entry = db.get(key)
		if entry:
			self.render("permalink.html",entry=entry)
		else:
			self.error(404)
			return

class User(db.Model):
	username = db.StringProperty(required = True)
	password_hash = db.StringProperty(required = True)
	email = db.EmailProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)


class Entry(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	date_created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n','<br>')
		return render_str("entry.html", entry = self)

app = webapp2.WSGIApplication([('/unit2/rot13',Rot13),
							   ('/blog/signup',Signup),
							   ('/blog/welcome',Welcome),
							   ('/blog/newpost',Submit),
							   ('/blog/([0-9]+)',Permalink),
							   ('/blog',FrontPage)],
							   debug=True)
