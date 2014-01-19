import time
import random
import string
import urlparse
import urllib
import hashlib

import tornado.web
import tornado.template
import tornado.auth
import tornado.escape


from setting import settings


import functools
from tornado import httpclient
from tornado import escape

class WeiboMixin(tornado.auth.OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = "https://api.weibo.com/oauth2/access_token"
    _OAUTH_AUTHORIZE_URL = "https://api.weibo.com/oauth2/authorize"

    @tornado.web.asynchronous
    def get_authenticated_user(self, redirect_uri, client_id, client_secret,
                               code, callback, extra_fields=None):
        http = httpclient.AsyncHTTPClient()

        fields = set()
        if extra_fields:
            fields.update(extra_fields)

        args = {
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "authorization_code"
        }

        http.fetch(self._OAUTH_ACCESS_TOKEN_URL,
            self.async_callback(self._on_access_token, redirect_uri, client_id, client_secret, callback, fields),
            method="POST", body=urllib.urlencode(args))

    @tornado.web.asynchronous
    def _on_access_token(self, redirect_uri, client_id, client_secret,
                         callback, fields, response):
        session = escape.json_decode(response.body)
        callback(session)


class WeiboHandler(tornado.web.RequestHandler,
                   WeiboMixin):
    @tornado.web.asynchronous
    def get(self):
        redirect_uri = "%s://%s%s" % (self.request.protocol, self.request.host, self.request.path)
        code = self.get_argument("code", None)
        if code:
            self.get_authenticated_user(redirect_uri, settings["WeiboAppKey"], settings["WeiboAppSecret"],
                                   code, self._on_auth)
            return
        self.authorize_redirect(redirect_uri,
                                client_id=settings["WeiboAppKey"],
                                extra_params={"response_type": "code"})

    def _on_auth(self, session):
        self.finish(session)


class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.redirect_url = self.get_argument("next", "/")
        self.clear_cookie("user")
        self.redirect(self.redirect_url)
