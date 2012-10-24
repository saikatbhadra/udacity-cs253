#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import string
import os
#import jinja2

#_template_dir = os.path.join(os.path.dirname(__file__), 'templates')
#_jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)

form = """
<html>
	<head>
		<title>Unit 2 HW</title>
	</head>
	<body>
		<h2> Enter some text to ROT13 </h2>
		<form method="post">
			<textarea name="text" style="height: 100px; width: 400px;">
				%(text_area)s
			</textarea>
			<br>
			<input type="submit">
		</form>
	</body>
</html>
"""

# def render_str(template, **params):
# 	t = _jinja_env.get_template(template)
# 	return t.render(params)

# def rot132(text,offset):
# 	out = ''
# 	aval = ord('a')	
# 	Aval = ord('A')
# 	alp_range = ord('z') - ord('a') + 1
 
# 	for char in text:
# 		char_num = ord(char)
# 		if (char_num >= ord('a')) and (char_num <= ord('z')):
# 			new_char = ((char_num - aval + offset) % alp_range) + aval
# 			new_char = chr(new_char)
# 			out += new_char
# 		elif (char_num >= ord('A')) and (char_num <= ord('Z')):
# 			new_char = ((char_num - Aval + offset) % alp_range) + Aval
# 			new_char = chr(new_char)
# 			out += new_char
# 		else:
# 			out += char

# 	return out

def rot13(text):
	rot13 = string.maketrans( "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
		"NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")
	out = string.translate(text, rot13)
	return out

# class BaseHandler(webapp2.RequestHandler):
# 	def render(self,template, **kw):
# 		self.response.out.write(render_str(template,**kw))
# 	def write(self,*a,**kw):
# 		self.response.out(*a,**kw)

# class Rot13(BaseHandler):
# 	def get(self):
# 		self.render('rot13.html')
# 	def post(self):
# 		enc_text = ''
# 		text = self.request.get('text'):
# 		if text:
# 			enc_text = rot132(text)
# 		self.render.('rot13.html',text = enc_text) 

class MainPage(webapp2.RequestHandler):
	def write_form(self, text_area=""):
		self.response.write(form % {"text_area": cgi.escape(text_area, quote = True)})
	def get(self):
		self.write_form()
	def post(self):
		text = self.request.get('text')
		new_text = rot13(text)
		self.write_form(new_text)

app = webapp2.WSGIApplication([('/', MainPage),('/unit2/rot13', Rot13)], debug=True)
