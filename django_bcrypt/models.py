import bcrypt

from django.conf import settings
from django.contrib.auth import models

def check_password(raw_password, enc_password):
    if enc_password[0] == '$':
        algo = enc_password[1:].split('$', 1)[0]
        assert algo in ('2a', '2', 'bcrypt')

        return enc_password == bcrypt.hashpw(raw_password, enc_password)

    return django_check_password(raw_password, enc_password)

def set_password(self, raw_password):
    if raw_password is None:
        self.set_unusable_password()
    else:
        self.password = bcrypt.hashpw(
            raw_password,
            bcrypt.gensalt(getattr(settings, 'BCRYPT_LOG_ROUNDS', 12)),
        )

if getattr(settings, 'USE_BCRYPT', True):
    django_check_password = models.check_password
    models.check_password = check_password
    models.User.set_password = set_password
