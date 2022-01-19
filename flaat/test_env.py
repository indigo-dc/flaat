import os


def _mandatory_env_var(name):
    env_var = f"FLAAT_{name}"
    val = os.environ.get(env_var, "")
    if val == "":
        raise ValueError(f"Environment variable is empty: {env_var}")

    return val


FLAAT_AT = _mandatory_env_var("AT")
FLAAT_CLAIM_ENTITLEMENT = _mandatory_env_var("CLAIM_ENTITLEMENT")
FLAAT_CLAIM_GROUP = _mandatory_env_var("CLAIM_GROUP")
FLAAT_ENTITLEMENT = _mandatory_env_var("ENTITLEMENT")
FLAAT_GROUP = _mandatory_env_var("GROUP")
FLAAT_ISS = _mandatory_env_var("ISS")

FLAAT_TRUSTED_OPS_LIST = [FLAAT_ISS]


PATH_LOGIN_REQUIRED = "/login_required"
PATH_GROUP_REQUIRED = "/group_required"
PATH_ENTITLEMENT_REQUIRED = "/entitlement_required"

# these paths correspond to the paths from the app fixtures
TEST_PATHS = [
    PATH_LOGIN_REQUIRED,
    PATH_GROUP_REQUIRED,
    PATH_ENTITLEMENT_REQUIRED,
]

STATUS_KWARGS_LIST = [
    # no token -> unauthorized
    (401, {}),
    # invalid access token -> unauthorized
    (
        401,
        {"headers": {"Authorization": "Bearer invalid_at"}},
    ),
    # good access token with the right entitlements
    (200, {"headers": {"Authorization": f"Bearer {FLAAT_AT}"}}),
]
