import os


def mandatory_env_var(name):
    env_var = f"FLAAT_{name}"
    val = os.environ.get(env_var, "")
    if val == "":
        raise ValueError(f"Environment variable is empty: {env_var}")

    return val


FLAAT_AT = mandatory_env_var("AT")
FLAAT_CLAIM_ENTITLEMENT = mandatory_env_var("CLAIM_ENTITLEMENT")
FLAAT_CLAIM_GROUP = mandatory_env_var("CLAIM_GROUP")
FLAAT_ENTITLEMENT = mandatory_env_var("ENTITLEMENT")
FLAAT_GROUP = mandatory_env_var("GROUP")
FLAAT_ISS = mandatory_env_var("ISS")
