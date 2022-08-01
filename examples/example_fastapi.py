# Flaat example with FastAPI
from fastapi import FastAPI, Response, Request
from flaat import AuthWorkflow
from flaat.config import AccessLevel
from flaat.fastapi import Flaat
from flaat.requirements import CheckResult, HasSubIss, IsTrue
from flaat.requirements import get_claim_requirement
from flaat.requirements import get_vo_requirement

from examples import logsetup


# ------------------------------------------------------------------
# Basic configuration example ---------------------------------------
logger = logsetup.setup_logging()
ADMIN_EMAILS = ["admin@foo.org", "dev@foo.org"]


# Standard fastapi blueprint snippet, source:
# https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/
app = FastAPI()
flaat = Flaat()


# Set a list of access levels to use
def is_admin(user_infos):
    return user_infos.user_info["email"] in ADMIN_EMAILS


flaat.set_access_levels(
    [
        AccessLevel("user", HasSubIss()),
        AccessLevel("admin", IsTrue(is_admin)),
    ]
)

flaat.set_trusted_OP_list(
    [
        "https://aai-demo.egi.eu/oidc",
        "https://aai-demo.egi.eu/auth/realms/egi",
        "https://aai-dev.egi.eu/oidc",
        "https://aai.egi.eu/oidc/",
        "https://aai.egi.eu/auth/realms/egi",
        "https://accounts.google.com/",
        "https://b2access-integration.fz-juelich.de/oauth2",
        "https://b2access.eudat.eu/oauth2/",
        "https://iam-test.indigo-datacloud.eu/",
        "https://iam.deep-hybrid-datacloud.eu/",
        "https://iam.extreme-datacloud.eu/",
        "https://login-dev.helmholtz.de/oauth2/",
        "https://login.elixir-czech.org/oidc/",
        "https://login.helmholtz-data-federation.de/oauth2/",
        "https://login.helmholtz.de/oauth2/",
        "https://oidc.scc.kit.edu/auth/realms/kit/",
        "https://orcid.org/",
        "https://proxy.demo.eduteams.org",
        "https://services.humanbrainproject.eu/oidc/",
        "https://unity.eudat-aai.fz-juelich.de/oauth2/",
        "https://unity.helmholtz-data-federation.de/oauth2/",
        "https://wlcg.cloud.cnaf.infn.it/",
    ]
)


# ------------------------------------------------------------------
# Routes definition -------------------------------------------------
@app.get("/")
def root():
    text = """This is an example for using flaat with Flask.
    The following endpoints are available:
        /info                       General info about the access_token
        /info_no_strict             General info without token validation
        /authenticated              Requires a valid user
        /authenticated_callback     Requires a valid user, uses a custom callback on error
        /authorized_level           Requires user to fit the specified access level
        /authorized_claim           Requires user to have one of two claims
        /authorized_vo              Requires user to have an entitlement
        /full_custom                Fully custom auth handling
    """
    return Response(text, media_type="text/plain")


# -------------------------------------------------------------------
# Call with user information ----------------------------------------
@app.get("/info")
@flaat.inject_user_infos()  # Fail if no valid authentication is provided
def info_strict_mode(request: Request, user_infos=None):
    return user_infos.toJSON()


@app.get("/info_no_strict")
@flaat.inject_user_infos(strict=False)  # Pass with invalid authentication
def info(user_infos=None):
    return user_infos.toJSON() if user_infos else "No userinfo"


# -------------------------------------------------------------------
# Endpoint which requires of an authenticated user ------------------
@app.get("/authenticated")
@flaat.is_authenticated()
def authenticated():
    return "This worked: there was a valid login"


# -------------------------------------------------------------------
# Instead of giving an error this will return the custom error
# response from `my_on_failure` -------------------------------------
def my_on_failure(exception, user_infos=None):
    text = f"""Custom callback 'my_on_failure' invoked:
        Error Message: {exception}
        User: {user_infos if user_infos else "No Auth"}
    """
    abort(401, description=text)


@app.get("/authenticated_callback")
@flaat.is_authenticated(on_failure=my_on_failure)
def authenticated_callback():
    return "This worked: there was a valid login"


# -------------------------------------------------------------------
# Endpoint which requires an access level ---------------------------
@app.get("/authorized_level")
@flaat.access_level("admin")
def authorized_level():
    return "This worked: user has the required rights"


# -------------------------------------------------------------------
# The user needs to satisfy a certain requirement -------------------
email_requirement = get_claim_requirement(
    ["admin@foo.org", "dev@foo.org"],
    claim="email",
    match=1,
)


@app.get("/authorized_claim")
@flaat.requires(email_requirement)
def authorized_claim():
    return "This worked: User has the claim"


# -------------------------------------------------------------------
# The user needs belong to a certain virtual organization -----------
vo_requirement = get_vo_requirement(
    [
        "urn:mace:egi.eu:group:test:foo",
        "urn:mace:egi.eu:group:test:bar",
    ],
    "mock_entitlements",
    match=2,
)


@app.get("/authorized_vo")
@flaat.requires(vo_requirement)
def authorized_vo():
    return "This worked: user has the required entitlement"


# -------------------------------------------------------------------
# For maximum customization use AuthWorkflow ------------------------
def my_request_check(user_infos, *args, **kwargs):
    if len(args) != 1:
        return CheckResult(False, "Missing request object")
    return CheckResult(True, "The request is allowed")


def my_process_args(user_infos, *args, **kwargs):
    """We can manipulate the view functions arguments here The user is
    already authenticated at this point, therefore we have `user_infos`,
    therefore we can base our manipulations on the users identity.
    """
    kwargs["email"] = user_infos.get("email", "")
    return (args, kwargs)


custom = AuthWorkflow(
    flaat,  # needs the flaat instance
    user_requirements=get_claim_requirement("bar", "foo"),
    request_requirements=my_request_check,
    process_arguments=my_process_args,
    on_failure=my_on_failure,
    ignore_no_authn=True,  # Don't fail if there is no authentication
)


@app.get("/full_custom")
@custom.decorate_view_func  # invoke the workflow here
def full_custom(email=""):
    text = f"""This worked: The custom workflow did succeed:
        The users email is: {email}
    """
    return Response(text, media_type="text/plain")


# -------------------------------------------------------------------
# Main function -----------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8081)
