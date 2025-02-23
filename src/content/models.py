from datetime import datetime
import os
import random
import string
from PIL import Image
import numpy as np
import pyclamd
import copy
from src import app, db
from src.utils import scan_file

class Tweet(db.Model):

	__tablename__ = "tweets"

	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.String(140), nullable=False)
	created_at = db.Column(db.DateTime, nullable=False)
	img = db.Column(db.String(20), nullable=True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) 
	is_signed = db.Column(db.Boolean, nullable=False, default=False)
	signature = db.Column(db.String, nullable=True)
	hashed_value = db.Column(db.String, nullable=True)

	def __init__(self, text, user_id, img, is_signed, signature, hashed_value):
		self.text = text
		self.user_id = user_id
		self.created_at = datetime.now()
		self.is_signed = is_signed
		self.signature = signature
		self.hashed_value = hashed_value
		if img:
			scan_file(img)
			result = Image.open(img)
			dir = os.path.join("src", app.config['UPLOAD_FOLDER'])
			filename = self._generate_unique_filename(dir)
			result.save(os.path.join(dir, filename))
			self.img = filename


	def __repr__(self):
		return f"<tweet {self.id} by {self.user_id}>"
	
	def _generate_unique_filename(self, directory):
		while True:
			filename = self._random_filename()+".jpg"
			full_path = os.path.join(directory, filename)
			if not os.path.exists(full_path):
				return filename
			
	def _random_filename(self):
		return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    