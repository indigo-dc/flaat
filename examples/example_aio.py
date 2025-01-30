import logging

from aiohttp import web
from flaat import AuthWorkflow
from flaat.aio import Flaat
from flaat.exceptions import FlaatException
from flaat.requirements import CheckResult
from flaat.requirements import get_claim_requirement
from flaat.requirements import get_vo_requirement
from flaat.user_infos import UserInfos

# do some log setup so we can see something
logging.basicConfig(level="WARNING")
logging.getLogger("flaat").setLevel("DEBUG")


##########
# aio application
app = web.Application()
routes = web.RouteTableDef()

# Our FLAAT instance
flaat = Flaat()

# Insert OPs that you trust here
flaat.set_trusted_OP_list(
    [
        "https://b2access.eudat.eu/oauth2/",
        "https://b2access-integration.fz-juelich.de/oauth2",
        "https://unity.helmholtz-data-federation.de/oauth2/",
        "https://login.helmholtz-data-federation.de/oauth2/",
        "https://login-dev.helmholtz.de/oauth2/",
        "https://login.helmholtz.de/oauth2/",
        "https://unity.eudat-aai.fz-juelich.de/oauth2/",
        "https://services.humanbrainproject.eu/oidc/",
        "https://accounts.google.com/",
        "https://login.elixir-czech.org/oidc/",
        "https://iam-test.indigo-datacloud.eu/",
        "https://iam.deep-hybrid-datacloud.eu/",
        "https://iam.extreme-datacloud.eu/",
        "https://aai.egi.eu/oidc/",
        "https://aai.egi.eu/auth/realms/egi",
        "https://aai-demo.egi.eu/auth/realms/egi",
        "https://aai-demo.egi.eu/oidc",
        "https://aai-dev.egi.eu/oidc",
        "https://oidc.scc.kit.edu/auth/realms/kit/",
        "https://proxy.demo.eduteams.org",
        "https://wlcg.cloud.cnaf.infn.it/",
        "https://proxy.eduteams.org/",
        "https://cilogon.org/",
        "https://keycloak.sso.gwdg.de/auth/realms/academiccloud",
    ]
)

# verbosity:
#     0: Errors
#     1: Warnings
#     2: Infos
#     3: Debug output
flaat.set_verbosity(3)


# # Required for using token introspection endpoint:
# flaat.set_client_id('')
# flaat.set_client_secret('')


# this will customize error responses for the user (used down below)
def my_on_failure(exception: FlaatException, user_infos: UserInfos = None):
    user = "no auth"
    if user_infos is not None:
        user = str(user_infos)
    return web.Response(
        text=f"Custom my_on_failure invoked:\nError Message: {exception}\nUser: {user}"
    )


@routes.get("/")
async def root(request):
    text = """This is an example for useing flaat with AIO. These endpoints are available:
    /info                       General info about the access_token (if provided)
    /authenticated              Requires a valid user
    /authenticated_callback     Requires a valid user, uses a custom callback on error
    /authorized_claim           Requires user to have one of two claims
    /authorized_vo              Requires user to have an entitlement
    /full_custom                Fully custom auth handling
        """
    return web.Response(text=text)


@routes.get("/info")
@flaat.inject_user_infos(
    strict=False,  # we don't fail if there is no user
)
async def info(
    request,
    user_infos: UserInfos = None,  # here is the variable that gets injected, this should have a default value
):
    message = "No userinfo"
    if user_infos is not None:
        message = user_infos.toJSON()

    return web.Response(text=message)


@routes.get("/authenticated")
@flaat.is_authenticated()
async def authenticated_user(request):
    return web.Response(text="This worked: there was a valid login")


@routes.get("/authenticated_callback")
@flaat.is_authenticated(
    on_failure=my_on_failure,  # called if there is no authentication
)
async def valid_user_own_callback(request):
    """instead of giving an error this will return the custom error response from `my_on_failure`"""
    return web.Response(text="This worked: there was a valid login")


@routes.get("/authorized_claim")
@flaat.requires(
    get_claim_requirement(  # the user needs to satisfy this requirement (having one of the email claims)
        ["admin@foo.org", "dev@foo.org"],
        claim="email",
        match=1,
    ),
)
async def authorized_claim(request):
    return web.Response(text="This worked: User has the claim")


@routes.get("/authorized_vo")
@flaat.requires(
    get_vo_requirement(
        [
            "urn:geant:h-df.de:group:m-team:feudal-developers",
            "urn:geant:h-df.de:group:MyExampleColab#unity.helmholtz.de",
        ],
        "eduperson_entitlement",
        match=1,
    )
)
async def authorized_vo(request):
    return web.Response(text="This worked: user has the required entitlement")


# If you need maxmimum customizability, there is AuthWorkflow:

# User requirements
user_reqs = get_claim_requirement("bar", "foo")


def my_request_check(user_infos: UserInfos, *args, **kwargs):
    if len(args) != 1:
        return CheckResult(False, "Missing request object")

    return CheckResult(True, "The request is allowed")


def my_process_args(user_infos: UserInfos, *args, **kwargs):
    """
    We can manipulate the view functions arguments here
    The user is already authenticated at this point, therefore we have `user_infos`,
    therefore we can base our manipulations on the users identity.
    """
    kwargs["email"] = user_infos.get("email", "")
    return (args, kwargs)


custom = AuthWorkflow(
    flaat,  # needs the flaat instance
    user_requirements=user_reqs,
    request_requirements=my_request_check,
    process_arguments=my_process_args,
    on_failure=my_on_failure,
    ignore_no_authn=True,  # Don't fail if there is no authentication
)


@routes.get("/full_custom")
@custom.decorate_view_func  # invoke the workflow here
async def full_custom(request, email=""):
    return web.Response(
        text=f"This worked: The custom workflow did succeed\nThe users email is: {email}"
    )


app.add_routes(routes)

##########
# Main

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8080)
