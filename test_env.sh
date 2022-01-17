echo Loading access token from oidc-agent. Once it expires, you have to source this script again.
export FLAAT_AT="$(oidc-token egi)"
export FLAAT_ISS="https://aai.egi.eu/oidc/"

export FLAAT_CLAIM_ENTITLEMENT="eduperson_entitlement"
export FLAAT_ENTITLEMENT="urn:mace:egi.eu:group:eosc-synergy.eu:role=member#aai.egi.eu"

export FLAAT_CLAIM_GROUP="eduperson_scoped_affiliation"
export FLAAT_GROUP="employee@kit.edu"
