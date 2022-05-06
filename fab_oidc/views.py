import os
from typing import List
from urllib.parse import quote

from flask import redirect, request, session, g, url_for
from flask_admin import expose
from flask_appbuilder.security.forms import LoginForm_oid
from flask_appbuilder.security.views import AuthView
from flask_login import login_user
from werkzeug.wrappers import Response as WerkzeugResponse

# Set the OIDC field that should be used as a username
USERNAME_OIDC_FIELD = os.getenv("USERNAME_OIDC_FIELD", default="preferred_username")
FIRST_NAME_OIDC_FIELD = os.getenv("FIRST_NAME_OIDC_FIELD", default="nickname")
LAST_NAME_OIDC_FIELD = os.getenv("LAST_NAME_OIDC_FIELD", default="name")


class AuthOIDCView(AuthView):
    login_template = "appbuilder/general/security/login_oid.html"
    oid_ask_for = ["email"]
    oid_ask_for_optional: List[str] = []

    @expose("/login/", methods=["GET", "POST"])
    def login(self, flag=True) -> WerkzeugResponse:
        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.loginhandler
        def handle_login():
            token_response = oidc.keycloak.authorize_access_token()
            user = oidc.keycloak.parse_id_token(token_response)

            if user is None:
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

                user = sm.add_user(
                    username=info.get(USERNAME_OIDC_FIELD),
                    first_name=info.get(FIRST_NAME_OIDC_FIELD),
                    last_name=info.get(LAST_NAME_OIDC_FIELD),
                    email=info.get("email"),
                    role=role,
                )

        @self.appbuilder.sm.oid.loginhandler
        def login_handler(self):
            if g.user is not None and g.user.is_authenticated:
                return redirect(self.appbuilder.get_url_for_index)
            form = LoginForm_oid()
            login_user(g.user, remember=False, force=False)
            if form.validate_on_submit():
                session["remember_me"] = form.remember_me.data
                redirect_uri = url_for('auth', _external=True)
                return oidc.keycloak.authorize_redirect(redirect_uri)
            return self.render_template(
                self.login_template,
                title=self.title,
                form=form,
                providers=self.appbuilder.sm.openid_providers,
                appbuilder=self.appbuilder,
            )

        return handle_login()

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
