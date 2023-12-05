# Flaat example with FastAPI
import logging
from fastapi import Depends, FastAPI, Request, Response
from fastapi.security import HTTPBasicCredentials, HTTPBearer
from flaat import AuthWorkflow
from flaat.config import AccessLevel
from flaat.fastapi import Flaat
from flaat.requirements import CheckResult, HasSubIss, IsTrue
from flaat.requirements import get_claim_requirement
from flaat.requirements import get_vo_requirement


# ------------------------------------------------------------------
# Basic configuration example ---------------------------------------
logging.basicConfig(level="WARNING")
logging.getLogger("flaat").setLevel("DEBUG")
logging.getLogger("urllib3").setLevel("DEBUG")
ADMIN_EMAILS = ["admin@foo.org", "dev@foo.org"]


# Standard fastapi blueprint snippet, source:
# https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/
app = FastAPI()
flaat = Flaat()
security = HTTPBearer()


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
        "https://proxy.eduteams.org/",
    ]
)


# ------------------------------------------------------------------
# Routes definition -------------------------------------------------
@app.get("/")
def root():
    text = """This is an example for using flaat with Flask.
    The following endpoints are available:
        /authenticated              Requires a valid user
        /authenticated_callback     Requires a valid user, uses a custom callback on error
        /authorized_level           Requires user to fit the specified access level
        /authorized_claim           Requires user to have one of two claims
        /authorized_vo              Requires user to have an entitlement
        /full_custom                Fully custom auth handling
    """
    return Response(text, media_type="text/plain")


# -------------------------------------------------------------------
# Endpoint which requires of an authenticated user ------------------
@app.get("/authenticated")
@flaat.is_authenticated()
def authenticated(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
):
    user_infos = flaat.get_user_infos_from_request(request)
    return "This worked: there was a valid login"


# -------------------------------------------------------------------
# Instead of giving an error this will return the custom error
# response from `my_own_failure` -------------------------------------
def my_own_failure(exception, user_infos=None):
    return "Custom callback 'my_own_failure' invoked"


@app.get("/authenticated_callback")
@flaat.is_authenticated(on_failure=my_own_failure)
def authenticated_callback(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
):
    user_infos = flaat.get_user_infos_from_request(request)
    return "This worked: there was a valid login"


# -------------------------------------------------------------------
# Endpoint which requires an access level ---------------------------
@app.get("/authorized_level")
@flaat.access_level("admin")
def authorized_level(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
):
    user_infos = flaat.get_user_infos_from_request(request)
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
def authorized_claim(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
):
    user_infos = flaat.get_user_infos_from_request(request)
    return "This worked: User has the claim"


# -------------------------------------------------------------------
# The user needs belong to a certain virtual organization -----------
vo_requirement = get_vo_requirement(
    [
        "urn:mace:egi.eu:group:eosc-synergy.eu",
        "urn:mace:egi.eu:group:mteam.data.kit.edu:perfmon.m.d.k.e",
    ],
    "eduperson_entitlement",
    match=2,
)

@app.get("/authorized_vo")
@flaat.requires(vo_requirement)
def authorized_vo(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
):
    user_infos = flaat.get_user_infos_from_request(request)
    return "This worked: user has the required entitlement(s)"


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
    on_failure=my_own_failure,
    ignore_no_authn=True,  # Don't fail if there is no authentication
)


@app.get("/full_custom")
@custom.decorate_view_func  # invoke the workflow here
def full_custom(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
):
    user_infos = flaat.get_user_infos_from_request(request)
    return "This worked: user has the required entitlement"


# -------------------------------------------------------------------
# Main function -----------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8081)
