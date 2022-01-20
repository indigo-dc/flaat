echo Loading access token from oidc-agent. Once it expires, you have to source this script again.
export FLAAT_AT="$(oidc-token egi)"
export FLAAT_ISS="https://aai.egi.eu/oidc/"

# These claims must point two lists of at least two elements
export FLAAT_CLAIM_ENTITLEMENT="eduperson_entitlement"
export FLAAT_CLAIM_GROUP="eduperson_scoped_affiliation"
