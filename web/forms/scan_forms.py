# web/forms/scan_form.py
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, IPAddress

class ScanForm(FlaskForm):
    target = StringField('Target (IP or Hostname)', validators=[DataRequired()])
    submit = SubmitField('Run Scan')
