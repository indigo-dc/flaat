from flask import Flask, request
from werkzeug import Response

from examples import logsetup
from flaat.flask import Flaat
from flaat.requirements import HasAARCEntitlement, HasGroup, ValidLogin

logger = logsetup.setup_logging()


##########
## Basic config
# FLASK
app = Flask(__name__)

# FLAAT
flaat = Flaat()
flaat.set_cache_lifetime(120)  # seconds; default is 300
flaat.set_trusted_OP_list(
    [
        "https://aai-demo.egi.eu/oidc",
        "https://aai-dev.egi.eu/oidc",
        "https://aai.egi.eu/oidc/",
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
# flaat.set_trusted_OP_file('/etc/oidc-agent/issuer.config')
# flaat.set_OP_hint("helmholtz")
# flaat.set_OP_hint("google")
flaat.set_timeout(3)

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


@app.route("/")
def root():
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
    return Response(text, mimetype="text/plain")


@app.route("/info")
@flaat.inject_user_infos
def info(user_infos=None):
    if user_infos is not None:
        return user_infos.toJSON()
    return "No user infos"


@app.route("/valid_user/<int:id>", methods=["POST", "GET"])
@flaat.requires(ValidLogin())
def valid_user_id(id):
    retval = ""
    if request.method == "POST":
        retval += "POST\n"
    if request.method == "GET":
        retval += "GET\n"
    retval += f"This worked: there was a valid login, and an id: {id}\n"
    return retval


@app.route("/valid_user")
@flaat.requires(ValidLogin())
def valid_user():
    return "This worked: there was a valid login\n"


@app.route("/valid_user_2")
@flaat.requires(ValidLogin(), on_failure=my_failure_callback)
def valid_user_own_callback():
    return "This worked: there was a valid login"


@app.route("/group_test_kit")
@flaat.requires(
    HasGroup(
        required=["admins@kit.edu", "employee@kit.edu", "member@kit.edu"],
        claim="eduperson_scoped_affiliation",
        match=2,
    ),
    on_failure=my_failure_callback,
)
def demo_groups_kit():
    return "This worked: user is member of the requested group"


@app.route("/group_test_iam")
@flaat.requires(HasGroup("KIT-Cloud", "groups"))
def demo_groups_iam():
    return "This worked: user is member of the requested group"


@app.route("/group_test_hdf")
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
def demo_groups_hdf():
    return "This worked: user is member of the requested group"


@app.route("/group_test_hdf2")
@flaat.requires(
    HasAARCEntitlement(
        "urn:geant:h-df.de:group:MyExampleColab", "eduperson_entitlement"
    )
)
def demo_groups_hdf2():
    return "This worked: user is member of the requested group"


@app.route("/group_test_hdf3")
@flaat.requires(
    HasAARCEntitlement(
        [
            "urn:geant:h-df.de:group:MyExampleColab",
            "urn:geant:h-df.de:group:m-team:feudal-developers",
        ],
        "eduperson_entitlement",
    )
)
def demo_groups_hdf3():
    return "This worked: user is member of the requested group"


##########
# Main
if __name__ == "__main__":
    # app.run(host="127.0.0.1", port=8081, debug=True)
    app.run(host="0.0.0.0", port=8081, debug=True)
