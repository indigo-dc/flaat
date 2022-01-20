
# the shortname depends on how you setup your oidc agent
export OIDC_AGENT_ACCOUNT="egi"

# the issuer of the oidc agent account
export FLAAT_ISS="https://aai.egi.eu/oidc/"

# These claims must point two lists of at least two elements in the userinfo
export FLAAT_CLAIM_ENTITLEMENT="eduperson_entitlement"
export FLAAT_CLAIM_GROUP="eduperson_scoped_affiliation"
