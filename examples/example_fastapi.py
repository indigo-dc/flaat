import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.security import HTTPBearer
from starlette.responses import PlainTextResponse

from examples import logsetup
from flaat.fastapi import Flaat
from flaat.requirements import HasAARCEntitlement, HasGroup, OneOf, ValidLogin
from flaat.user_infos import UserInfos

logger = logsetup.setup_logging()


##########
## Basic config
# FastAPI
app = FastAPI()
# default_response_class=HTMLResponse
security = HTTPBearer()

# FLAAT
flaat = Flaat()
flaat.set_cache_lifetime(120)  # seconds; default is 300
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
        "https://aai-demo.egi.eu/oidc",
        "https://aai-dev.egi.eu/oidc",
        "https://oidc.scc.kit.edu/auth/realms/kit/",
        "https://proxy.demo.eduteams.org",
        "https://wlcg.cloud.cnaf.infn.it/",
    ]
)
# flaat.set_trusted_OP_file('/etc/oidc-agent/issuer.config')
# flaat.set_OP_hint("helmholtz")
# flaat.set_OP_hint("google")

# verbosity:
#     0: No output
#     1: Errors
#     2: More info, including token info
#     3: Max
# flaat.set_verbosity(0)
# flaat.set_verify_tls(True)


# # Required for using token introspection endpoint:
# flaat.set_client_id('')
# flaat.set_client_secret('')

# flaat.raise_error_on_return = False


def my_failure_callback(message=""):
    return f"User define failure callback.\nError Message: {message}"


@app.get("/")
async def root(request: Request):
    text = """This is an example for useing flaat with FastAPI. These endpoints are available:
    /user_info          General info about the access_token (if provided)
    /user               User built using method
    /valid_user         Requires a valid user
    /valid_user_2       Requires a valid user, uses a custom callback on error
    /group_test_kit     Requires user to have two "eduperson_scoped_affiliation" of
                            ['admins@kit.edu', 'employee@kit.edu', 'member@kit.edu'],
    /group_test_iam     Requires user to be in the group "KIT-Cloud" transported in "groups"
    /group_test_hdf     Requires user to be in all groups found in "eduperson_entitlement"
                            ['urn:geant:h-df.de:group:aai-admin', 'urn:geant:h-df.de:group:myExampleColab#unity.helmholtz-data-federation.de']

    /group_test_hdf2     Requires user to be in all groups found in "eduperson_entitlement"
                            ['urn:geant:h-df.de:group:myExampleColab#unity.helmholtz-data-federation.de'],
    /group_test_hdf3     Requires user to be in all groups found in "eduperson_entitlement"
                            ['urn:geant:h-df.de:group:aai-admin'],
    /group_test_hack    A hack to use any other field for authorisation
    /group_test_wlcg    Requires user to be in the '/wlcg' group
        """
    return PlainTextResponse(text)


@app.get("/info")
@flaat.inject_user_infos
async def user_info(request: Request, user_infos=None):
    if user_infos is not None:
        return {"data": user_infos.__dict__}

    return {"message": "no userinfo"}


def get_user(user_infos: UserInfos):
    return {"infos": user_infos}


@app.get("/info")
@flaat.inject_user_infos
async def user(request: Request, user_infos=None):
    if user_infos is not None:
        return {"data": user_infos.__dict__}

    return {"message": "no userinfo"}


@app.get("/valid_user", dependencies=[Depends(security)])
@flaat.requires(ValidLogin())
def valid_user(request: Request):
    return {"message": "This worked: there was a valid login"}


@app.get("/valid_user_2", dependencies=[Depends(security)])
@flaat.requires(ValidLogin(), on_failure=my_failure_callback)
async def valid_user_own_callback(request: Request):
    return {"message": "This worked: there was a valid login"}


@app.get("/group_test_kit", dependencies=[Depends(security)])
@flaat.requires(
    HasGroup(
        required=["admins@kit.edu", "employee@kit.edu", "member@kit.edu"],
        claim="eduperson_scoped_affiliation",
        match=2,
    ),
    on_failure=my_failure_callback,
)
async def demo_groups_kit(request: Request):
    return {"message": "This worked: user is member of the requested group"}


@app.get("/group_test_iam", dependencies=[Depends(security)])
@flaat.requires(HasGroup("KIT-Cloud", "groups"))
async def demo_groups_iam(request: Request):
    return {"message": "This worked: user is member of the requested group"}


@app.get("/group_test_hdf", dependencies=[Depends(security)])
@flaat.requires(
    HasAARCEntitlement(
        required=[
            "urn:geant:h-df.de:group:m-team:feudal-developers",
            "urn:geant:h-df.de:group:MyExampleColab#unity.helmholtz.de",
        ],
        claim="eduperson_entitlement",
        match="all",
    )
)
async def demo_groups_hdf(request: Request):
    return {"message": "This worked: user has the required entitlement(s)"}


@app.get("/group_test_hdf2", dependencies=[Depends(security)])
@flaat.requires(
    HasAARCEntitlement(
        "urn:geant:h-df.de:group:MyExampleColab", "eduperson_entitlement"
    )
)
async def demo_groups_hdf2(request: Request):
    return {"message": "This worked: user has the required entitlement(s)"}


@app.get("/group_test_hdf3", dependencies=[Depends(security)])
@flaat.requires(
    HasAARCEntitlement(
        [
            "urn:geant:h-df.de:group:MyExampleColab",
            "urn:geant:h-df.de:group:m-team:feudal-developers",
        ],
        "eduperson_entitlement",
    )
)
async def demo_groups_hdf3(request: Request):
    return {"message": "This worked: user has the required entitlement(s)"}


@app.get("/group_test_hack", dependencies=[Depends(security)])
@flaat.requires(
    OneOf(
        HasGroup("Hardt", "family_name"),
        HasGroup("/wlcg", "wlcg.groups"),
    )
)
@app.get("/group_test_wlcg", dependencies=[Depends(security)])
async def demo_groups_wlcg(request: Request):
    return {"message": "This worked: user has the required Group Membership"}


@app.get("/role_test_egi", dependencies=[Depends(security)])
@flaat.requires(
    HasAARCEntitlement(
        "urn:mace:egi.eu:group:mteam.data.kit.edu:role=member",
        "eduperson_entitlement",
    )
)
async def demo_role_egi(request: Request):
    return {"message": "This worked: user is member of the requested group and role"}


##########
# Main

if __name__ == "__main__":
    uvicorn.run(
        "examples.example_fastapi:app", host="0.0.0.0", port=8082, log_level="info"
    )

# start with:
#   python3 example-fastapi.py
# or
#   uvicorn example-fastapi:app --host 0.0.0.0 --port 8082
