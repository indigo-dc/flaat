import json

from flask import Flask, request
from werkzeug import Response

from examples import logsetup
from flaat.flask import Flaat

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
        "https://orcid.org/",
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
    return 'User define failure callback.\nError Message: "%s"' % message


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
        return json.dumps(
            user_infos.__dict__, sort_keys=True, indent=4, separators=(",", ": ")
        )
    return "No user infos"


@app.route("/valid_user/<int:id>", methods=["POST", "GET"])
@flaat.login_required()
def valid_user_id(id):
    retval = ""
    if request.method == "POST":
        retval += "POST\n"
    if request.method == "GET":
        retval += "GET\n"
    retval += f"This worked: there was a valid login, and an id: {id}\n"
    return retval


@app.route("/valid_user")
@flaat.login_required()
def valid_user():
    return "This worked: there was a valid login\n"


@app.route("/valid_user_2")
@flaat.login_required(on_failure=my_failure_callback)
def valid_user_own_callback():
    return "This worked: there was a valid login"


@app.route("/group_test_kit")
@flaat.group_required(
    group=["admins@kit.edu", "employee@kit.edu", "member@kit.edu"],
    claim="eduperson_scoped_affiliation",
    match=2,
    on_failure=my_failure_callback,
)
def demo_groups_kit():
    return "This worked: user is member of the requested group"


@app.route("/group_test_iam")
@flaat.group_required(group="KIT-Cloud", claim="groups")
def demo_groups_iam():
    return "This worked: user is member of the requested group"


@app.route("/group_test_hdf")
@flaat.aarc_g002_entitlement_required(
    entitlement=[
        "urn:geant:h-df.de:group:m-team:feudal-developers",
        "urn:geant:h-df.de:group:MyExampleColab#unity.helmholtz.de",
    ],
    claim="eduperson_entitlement",
    match="all",
)
def demo_groups_hdf():
    return "This worked: user is member of the requested group"


@app.route("/group_test_hdf2")
@flaat.aarc_g002_entitlement_required(
    entitlement=["urn:geant:h-df.de:group:MyExampleColab"],
    claim="eduperson_entitlement",
    match="all",
)
def demo_groups_hdf2():
    return "This worked: user is member of the requested group"


@app.route("/group_test_hdf3")
@flaat.aarc_g002_entitlement_required(
    entitlement=[
        "urn:geant:h-df.de:group:MyExampleColab",
        "urn:geant:h-df.de:group:m-team:feudal-developers",
    ],
    claim="eduperson_entitlement",
    match="all",
)
def demo_groups_hdf3():
    return "This worked: user is member of the requested group"


@app.route("/group_test_hack")
@flaat.group_required(group=["Hardt"], claim="family_name", match="all")
def demo_groups_hack():
    return {"message": "This worked: user has the required Group Membership"}


@app.route("/group_test_wlcg")
@flaat.group_required(group="/wlcg", claim="wlcg.groups", match="all")
def demo_groups_wlcg():
    return {"message": "This worked: user has the required Group Membership"}


@app.route("/role_test_egi")
@flaat.aarc_g002_entitlement_required(
    entitlement=["urn:mace:egi.eu:group:mteam.data.kit.edu:role=member"],
    claim="eduperson_entitlement",
    match="all",
)
def demo_role_egi():
    return "This worked: user is member of the requested group and role"


##########
# Main
if __name__ == "__main__":
    # app.run(host="127.0.0.1", port=8081, debug=True)
    app.run(host="0.0.0.0", port=8081, debug=True)
