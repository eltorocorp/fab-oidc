import os
from typing import List
from urllib.parse import quote

from flask import redirect, request, session, g, flash
from flask_admin import expose
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.forms import LoginForm_oid
from flask_appbuilder.security.views import AuthOIDView
from flask_appbuilder.utils.base import get_safe_redirect
from flask_login import login_user
from werkzeug.wrappers import Response as WerkzeugResponse

# Set the OIDC field that should be used as a username
USERNAME_OIDC_FIELD = os.getenv("USERNAME_OIDC_FIELD", default="preferred_username")
FIRST_NAME_OIDC_FIELD = os.getenv("FIRST_NAME_OIDC_FIELD", default="nickname")
LAST_NAME_OIDC_FIELD = os.getenv("LAST_NAME_OIDC_FIELD", default="name")


class AuthOIDCView(AuthOIDView):
    login_template = "appbuilder/general/security/login_oid.html"
    oid_ask_for = ["email"]
    oid_ask_for_optional: List[str] = []

    @expose("/auth/", methods=["GET", "POST"])
    def auth(self):
        tokenResponse = self.appbuilder.sm.oid.keycloak.authorize_access_token()

        # userinfo = oauth.keycloak.userinfo(request)
        user = self.appbuilder.sm.oid.keycloak.parse_id_token(tokenResponse)

        if user:
            session["user"] = user
            session["tokenResponse"] = tokenResponse

        return redirect("/")

    @expose("/login/", methods=["GET", "POST"])
    def login(self, flag=True) -> WerkzeugResponse:
        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.loginhandler
        def login_handler(self):
            if g.user is not None and g.user.is_authenticated:
                return redirect(self.appbuilder.get_url_for_index)
            form = LoginForm_oid()
            if form.validate_on_submit():
                session["remember_me"] = form.remember_me.data
                return self.appbuilder.sm.oid.try_login(
                    form.openid.data,
                    ask_for=self.oid_ask_for,
                    ask_for_optional=self.oid_ask_for_optional,
                )
            return self.render_template(
                self.login_template,
                title=self.title,
                form=form,
                providers=self.appbuilder.sm.openid_providers,
                appbuilder=self.appbuilder,
            )

        @self.appbuilder.sm.oid.after_login
        def after_login(resp):
            if resp.email is None or resp.email == "":
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login)
            user = self.appbuilder.sm.auth_user_oid(resp.email)
            if user is None:
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login)
            remember_me = False
            if "remember_me" in session:
                remember_me = session["remember_me"]
                session.pop("remember_me", None)

            # Do the stuff from https://gist.github.com/thomasdarimont/6a3905778520b746ff009cf3a41643e9
            # here, and for reference https://docs.authlib.org/en/latest/client/flask.html

            token_response = oidc.keycloak.authorize_access_token()
            user = oidc.keycloak.parse_id_token(token_response)

            # info should be a dict with keys of the array given as input to user_getinfo
            info = oidc.user_getinfo(
                [
                    USERNAME_OIDC_FIELD,
                    FIRST_NAME_OIDC_FIELD,
                    LAST_NAME_OIDC_FIELD,
                    "email",
                    "groups",
                ]
            )

            if "airflow-admin" in info.get("groups"):
                role = sm.find_role("Admin")
            elif "airflow-operator" in info.get("groups"):
                role = sm.find_role("Op")
            else:
                role = sm.find_role(sm.auth_user_registration_role)

            ###### Work ends here

            login_user(user, remember=remember_me)
            next_url = request.args.get("next", "")

            return redirect(get_safe_redirect(next_url))

        return login_handler(self)

    @expose("/logout/", methods=["GET", "POST"])
    def logout(self):

        oidc = self.appbuilder.sm.oid

        oidc.logout()
        super(AuthOIDCView, self).logout()
        redirect_url = request.url_root.strip("/") + self.appbuilder.get_url_for_login

        logout_uri = (
            oidc.client_secrets.get("issuer")
            + "/protocol/openid-connect/logout?redirect_uri="
        )
        if "OIDC_LOGOUT_URI" in self.appbuilder.app.config:
            logout_uri = self.appbuilder.app.config["OIDC_LOGOUT_URI"]

        return redirect(logout_uri + quote(redirect_url))
