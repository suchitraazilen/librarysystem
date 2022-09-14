from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class TokenGenerator(PasswordResetTokenGenerator):

    def _make_hash_value(self, updated, timestamp):
        return (six.text_type(updated.pk) + six.text_type(timestamp) +six.text_type(updated.is_active))

set_password_token = TokenGenerator()