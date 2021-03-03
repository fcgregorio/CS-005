from nltk.corpus import words as nltk_words
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, ValidationError, HiddenField


def check_has_upper_lower_number_special(form, field):
    special_chars = r""" !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
    password = field.data

    if not any(char.islower() for char in password) or \
        not any(char.isupper() for char in password) or \
        not any(char.isdigit() for char in password) or \
        not any((char in special_chars) for char in password):
        raise ValidationError('Must consist of at least 1 upper case letter, 1 lower case letter, 1 number, and 1 special character.')


def check_does_not_contain_username_first_name_last_name(form, field):
    username = form.username.data.lower()
    first_name = form.first_name.data.lower()
    last_name = form.username.data.lower()
    password = field.data.lower()

    if (username in password) or \
        (first_name in password) or \
        (last_name in password):
        raise ValidationError('Must not contain the username, first name, or last name.')


def check_has_no_dictionary_words_greater_than_4_characters(form, field):
    password = field.data.lower()

    if len(password) > 3:
        set_of_words = set(nltk_words.words())

        for i in range(len(password)):
            for j in range(i + 1, len(password) + 1):
                word = password[i: j]
                if len(word) > 3 and word in set_of_words:
                    raise ValidationError('Must not contain dictionary words longer than 3 letters.')


class RegistrationForm(Form):
    first_name = StringField('First Name', [
        validators.DataRequired(),
        validators.Length(max=50),
    ])
    last_name = StringField('Last Name', [
        validators.DataRequired(),
        validators.Length(max=50),
    ])
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(max=25),
    ])
    email = StringField('Email Address', [
        validators.DataRequired(),
        validators.Email()
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=10),
        check_has_upper_lower_number_special,
        check_does_not_contain_username_first_name_last_name,
        check_has_no_dictionary_words_greater_than_4_characters,
        validators.EqualTo('confirm_password', message='Passwords must match'),
    ])
    confirm_password = PasswordField('Repeat Password', [
        validators.DataRequired(),
    ])


class LoginForm(Form):
    username = StringField('Username', [
        validators.DataRequired(),
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
    ])


class PasswordChangeForm(Form):
    first_name = HiddenField()
    last_name = HiddenField()
    username = HiddenField()
    password = PasswordField('Password', [
        validators.DataRequired(),
    ])
    new_password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.Length(min=10),
        check_has_upper_lower_number_special,
        check_does_not_contain_username_first_name_last_name,
        check_has_no_dictionary_words_greater_than_4_characters,
        validators.EqualTo('new_confirm_password', message='New Passwords must match'),
    ])
    new_confirm_password = PasswordField('Repeat New Password', [
        validators.DataRequired(),
    ])


class UpdateUserForm(Form):
    first_name = StringField('First Name', [
        validators.DataRequired(),
        validators.Length(max=50),
    ])
    last_name = StringField('Last Name', [
        validators.DataRequired(),
        validators.Length(max=50),
    ])
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(max=25),
    ])
    email = StringField('Email Address', [
        validators.DataRequired(),
        validators.Email()
    ])


class MessageForm(Form):
    content = TextAreaField('Content', [
        validators.DataRequired(),
        validators.Length(max=255),
    ])
