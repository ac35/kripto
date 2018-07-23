from datetime import datetime
from flask import render_template, flash, redirect, url_for, request, abort, send_file
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from app import app, db
from app.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, ResetPasswordForm, EncryptForm, DecryptForm
from app.models import User, Cipherfile, Message
from app.auth.email import send_password_reset_email, send_confirmation_link_email
from app.decorators import check_confirmed

import os
import hashlib
from io import BytesIO
from kripto_core.pbkdf2 import pbkdf2
from kripto_core.rsa import rsa_cipher
from kripto_core.salsa20 import Salsa20


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()


@app.route('/')
@app.route('/index')
# @login_required
def index():
    return render_template('index.html', title='Home')


@app.route('/user/<username>')
@login_required
@check_confirmed
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)


@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
@check_confirmed
def encrypt():
    form = EncryptForm(sender=current_user)
    if form.validate_on_submit():
        file = form.file.data
        base_key = form.base_key.data
        recipient = User.query.get(form.recipient.data) # instance objek user
        data = file.read()  # data dlm bytes (stream)
        comment = form.comment.data  # comment (pesan) untuk message

        # proses digital signature digest
        digest = hashlib.sha256(data).digest()
        signed_digest = rsa_cipher.digital_signature(current_user.get_private_key(), digest)

        # enkripsi kunci Salsa20
        s20_key = pbkdf2(base_key)
        enc_s20_key = rsa_cipher.encrypt(recipient.get_public_key(), s20_key)

        # enkripsi data dari file
        nonce = os.urandom(8)
        s20 = Salsa20(s20_key, nonce)
        enc_data = s20.encrypt(data)
        enc_data = nonce + enc_data

        # buat instance object cipherfile
        cipherfile = Cipherfile(
            filename=secure_filename(file.filename),
            file_type=file.content_type,
            file_length=len(data),
            content=enc_data, # data yang telah dienkripsi dlm bytes <--
            encrypted_s20_key=enc_s20_key,
            signed_digest=signed_digest
        )
        db.session.add(cipherfile)

        # buat instance object message
        message = Message(
            sender=current_user,
            recipient=recipient,
            cipherfile=cipherfile,
            comment=comment,
        )
        db.session.add(message)
        db.session.commit()

        flash('File {} has been sucessfully encrypted.'.format(cipherfile.filename), 'success')    # success
        # return '{} {} {}'.format(filename, recipient.username, len(data))
        return redirect(url_for('outbox'))
    return render_template('encrypt.html', title='Encrypt', form=form)


@app.route('/decrypt/<message_id>', methods=['GET', 'POST'])
@login_required
@check_confirmed
def decrypt(message_id):
    message = Message.query.filter(Message.id == message_id).first_or_404()
    if message.recipient != current_user:
        abort(403)  # mencoba decrypt message yang recipientnya bukan current_user
    if message.inbox_status == Message.status['has_been_deleted']:
        abort(404)
    form = DecryptForm(recipient=current_user)
    if form.validate_on_submit():
        sender = message.sender
        cipherfile = message.cipherfile

        # dekripsi kunci s20 terenkripsi
        dec_s20_key = rsa_cipher.decrypt(current_user.get_private_key(), cipherfile.encrypted_s20_key)

        # dekripsi cipherfile
        nonce = cipherfile.content[:8]  # ambil nonce
        enc_data = cipherfile.content[8:]   # ambil encrypted data (bytes)
        s20 = Salsa20(dec_s20_key, nonce)
        dec_data = s20.decrypt(enc_data)    # data hasil dekripsi (decrypted data)

        # dekripsi signed digest
        dec_digest = rsa_cipher.decrypt_signature(sender.get_public_key(), cipherfile.signed_digest)

        # bandingkan digest
        digest_from_dec_data = hashlib.sha256(dec_data).digest()
        if not digest_from_dec_data == dec_digest:
            abort(500)  #  digest tidak cocok

        # download file
        flash('File {} has been sucessfully decrypted.'.format(cipherfile.filename), 'success')    # success
        return send_file(BytesIO(dec_data), mimetype=cipherfile.file_type, as_attachment=True, attachment_filename=cipherfile.filename)

    return render_template('decrypt.html', title='Decrypt', form=form, message=message)


@app.route('/inbox')
@login_required
@check_confirmed
def inbox():
    messages = current_user.get_messages_from_inbox() or []   # nanti dibuat paginate?
    if not messages:
        flash('Your inbox is empty.', 'info')   # info
    return render_template('inbox.html', title='Inbox', messages=messages)


@app.route('/outbox')
@login_required
@check_confirmed
def outbox():
    messages = current_user.get_messages_from_outbox() or []    # nanti dibuat paginate?
    if not messages:
        flash('Your outbox is empty.', 'info')   # info
    return render_template('outbox.html', title='Outbox', messages=messages)


@app.route('/about')
def about():
    user = User.query.filter_by(email='alvinchandra783@gmail.com').first()
    return render_template('about.html', title='About', user=user)


@app.route('/delete_inbox/<message_id>')
@login_required
@check_confirmed
def delete_inbox(message_id):
    message = Message.query.filter(Message.id == message_id).first_or_404()
    if message.recipient != current_user:
        abort(403)  # mencoba delete message yang recipientnya bukan current_user
    if message.inbox_status == Message.status['default']:
        message.inbox_status = Message.status['has_been_deleted']
        db.session.add(message)
        db.session.commit()
        flash('Message has been deleted.', 'success')
    return redirect(url_for('inbox'))


@app.route('/delete_outbox/<message_id>')
@login_required
@check_confirmed
def delete_outbox(message_id):
    message = Message.query.filter(Message.id == message_id).first_or_404()
    if message.sender != current_user:
        abort(403)  # mencoba delete message yang recipientnya bukan current_user
    if message.outbox_status == Message.status['default']:
        message.outbox_status = Message.status['has_been_deleted']
        db.session.add(message)
        db.session.commit()
        flash('Message has been deleted.', 'success')
    return redirect(url_for('outbox'))