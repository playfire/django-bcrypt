"""
:mod:`django-bcrypt` --- bcrypt support for Django
==================================================

`Django <http://www.djangoproject.com/>`_ ships with support for the following
password hash algorithms:

 * SHA1 (default)
 * MD5 (deprecated)
 * crypt

These are general purpose functions, designed to calculate a digest in as short
a time as possible. However, being fast is not a desirable property for a
digest function for storing passwords: a modern computer can calculate the SHA1
hash of hundreds of megabytes every second. If your users have passwords which
are lowercase, alphanumeric, and 6 characters long, you can try every single
possible password of that size in less than a minute. Django's passwords are
salted, but this doesn't affect how fast an attacker can try a password given
the hash and the salt from your database.

`bcrypt <http://bcrypt.sourceforge.net/>`_ solves this problem by being
extremely slow - with a "work factor" of 12, bcrypt is approximately 4 orders
of magnitude slower than SHA1. Instead of a single minute to a crack a short
password of the kind described above, would take an entire day. Futhermore,
this work factor is configurable so it can be increased as computers get
faster.


Installation
------------

1. `py-bcrypt <http://www.mindrot.org/projects/py-bcrypt/>`_
   (``python-bcrypt`` on Debian GNU/Linux and derivatives)

2. Add ``django_bcrypt`` to your ``INSTALLED_APPS``::

    INSTALLED_APPS = (
        ...
        'django_bcrypt',
        ...
    )

3. That's it. New passwords (eg. for new users or when changing/resetting your
   password) will now use bcrypt::

    > SELECT id, username, password FROM auth_user WHERE username = 'lamby';
    +-------+----------+--------------------------------------------------------------+
    | id    | username | password                                                     |
    +-------+----------+--------------------------------------------------------------+
    | 15670 | lamby    | $2a$12$BENgnHkhQxDQ2t51g260ueUFEa9bQiBrJpS42p8v58AcD0.hllMw6 |
    +-------+----------+--------------------------------------------------------------+
    1 row in set (0.00 sec)


Migrating existing SHA1 passwords to bcrypt
-------------------------------------------

Simply using ``django-bcrypt`` will result in new passwords (either for new
users or users who use any change/forgotten password feature) to be encoded
using the bcrypt algorithm. You cannot en-masse migrate existing SHA1 hashes as
they are by-definition not reversible.

However, you can convert users' passwords when they login next::

    def login(request):
        if request.method == 'POST':
            form = AuthenticationForm(request.POST)

            if form.is_valid():
                user = form.get_user()

                if user.password.startswith('sha1'):
                    user.set_password(form['password'])
                    user.save()

                # [etc]

Configuration
-------------

``USE_BCRYPT``
~~~~~~~~~~~~~~

Default: ``True``

Use this setting to disable bcrypt password support. This is useful when
running your testsuite - these ephemeral users do not require security and
their passwords can take some time to generate.

``BCRYPT_LOG_ROUNDS``
~~~~~~~~~~~~~~~~~~~~~

Default: ``12``

The number of rounds determines the complexity of the bcrypt algorithm. The
work factor is 2**log_rounds, and the default is 12

This setting can be changed at any time without invalidating
previously-generated hashes.

Links
-----

View/download code
  https://github.com/playfire/django-cache-backed-auth

File a bug
  https://github.com/playfire/django-cache-backed-auth/issues
"""

import bcrypt

from django.conf import settings
from django.contrib.auth import models
from django.utils.crypto import constant_time_compare
from django.utils.encoding import smart_str

def check_password(raw_password, enc_password):
    if enc_password[0] == '$':
        algo = enc_password[1:].split('$', 1)[0]
        assert algo in ('2a', '2', 'bcrypt')

        return constant_time_compare(
            enc_password,
            bcrypt.hashpw(smart_str(raw_password), enc_password),
        )

    return django_check_password(raw_password, enc_password)

def set_password(self, raw_password):
    if raw_password is None:
        self.set_unusable_password()
    else:
        self.password = bcrypt.hashpw(
            smart_str(raw_password),
            bcrypt.gensalt(getattr(settings, 'BCRYPT_LOG_ROUNDS', 12)),
        )

if getattr(settings, 'USE_BCRYPT', True):
    django_check_password = models.check_password
    models.check_password = check_password
    models.User.set_password = set_password
