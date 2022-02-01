import json

from aiohttp import web

from examples.logsetup import setup_logging
from flaat.aio import Flaat
from flaat.requirements import HasAARCEntitlement, HasGroup, ValidLogin
from flaat.user_infos import UserInfos

setup_logging()


##########
## Basic config
# AIOHTTP
app = web.Application()
routes = web.RouteTableDef()

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


def my_failure_callback(message=""):
    return f"User define failure callback.\nError Message: {message}"


@routes.get("/")
async def root(request):
    text = """This is an example for useing flaat with AIO. These endpoints are available:
    /info               General info about the access_token (if provided)
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
    return web.Response(text=text)


@routes.get("/info")
async def info(request):
    infos = flaat.get_all_info_from_request(request)
    x = json.dumps(infos.__dict__, sort_keys=True, indent=4, separators=(",", ": "))
    return web.Response(text=str(x))


@routes.get("/info2")
@flaat.inject_user_infos
async def info2(request, user_infos: UserInfos = None):
    if user_infos is not None:
        message = json.dumps(
            user_infos.__dict__, sort_keys=True, indent=4, separators=(",", ": ")
        )
        return web.Response(text=message)

    return web.Response(text="No userinfo")


@routes.get("/valid_user")
@flaat.requires(ValidLogin())
async def valid_user(request):
    return web.Response(text="This worked: there was a valid login")


@routes.get("/valid_user_2")
@flaat.requires(ValidLogin(), on_failure=my_failure_callback)
async def valid_user_own_callback(request):
    return web.Response(text="This worked: there was a valid login")


@routes.get("/group_test_kit")
@flaat.requires(
    HasGroup(
        ["admins@kit.edu", "employee@kit.edu", "member@kit.edu"],
        claim="eduperson_scoped_affiliation",
        match=2,
    ),
    on_failure=my_failure_callback,
)
async def demo_groups_kit(request):
    return web.Response(text="This worked: user is member of the requested group")


@routes.get("/group_test_iam")
@flaat.requires(HasGroup("KIT-Cloud", "groups"))
async def demo_groups_iam(request):
    return web.Response(text="This worked: user is member of the requested group")


@routes.get("/group_test_hdf")
@flaat.requires(
    HasAARCEntitlement(
        [
            "urn:geant:h-df.de:group:m-team:feudal-developers",
            "urn:geant:h-df.de:group:MyExampleColab#unity.helmholtz.de",
        ],
        "eduperson_entitlement",
    )
)
async def demo_groups_hdf(request):
    return web.Response(text="This worked: user has the required entitlement(s)")


@routes.get("/group_test_hdf2")
@flaat.requires(
    HasAARCEntitlement(
        "urn:geant:h-df.de:group:MyExampleColab",
        "eduperson_entitlement",
    )
)
async def demo_groups_hdf2(request):
    return web.Response(text="This worked: user has the required entitlement(s)")


@routes.get("/group_test_hdf3")
@flaat.requires(
    HasAARCEntitlement(
        [
            "urn:geant:h-df.de:group:MyExampleColab",
            "urn:geant:h-df.de:group:m-team:feudal-developers",
        ],
        "eduperson_entitlement",
    )
)
async def demo_groups_hdf3(request):
    return web.Response(text="This worked: user has the required entitlement(s)")


@routes.get("/group_test_hack")
@flaat.requires(HasGroup("Hardt", claim="family_name"))
async def demo_groups_hack(request):
    return web.Response(text="This worked: user has the required Group Membership")


@routes.get("/group_test_wlcg")
@flaat.requires(HasGroup("/wlcg", "wlcg.groups"))
async def demo_groups_wlcg(request):
    return web.Response(text="This worked: user has the required Group Membership")


@routes.get("/role_test_egi")
@flaat.requires(
    HasAARCEntitlement(
        "urn:mace:egi.eu:group:mteam.data.kit.edu:role=member",
        "eduperson_entitlement",
    )
)
async def demo_role_egi(request):
    return web.Response(
        text="This worked: user is member of the requested group and role"
    )


app.add_routes(routes)

##########
# Main

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8083)
