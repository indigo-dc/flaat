from dataclasses import dataclass

import pytest
from jwt.api_jwt import decode_complete

from flaat import BaseFlaat, flaat_userinfo
from flaat.flaat_userinfo import (
    TRUSTED_OP_LIST,
    UserInfosPrinter,
    get_access_token,
    get_flaat,
    main,
)
from flaat.test_env import (
    FLAAT_AT,
    FLAAT_CLIENT_ID,
    FLAAT_CLIENT_SECRET,
    FLAAT_ISS,
    OIDC_AGENT_ACCOUNT,
    AUD_OIDC_AGENT_ACCOUNT,
)


@dataclass
class ArgsMock:
    quiet = False
    verbose = True
    issuer = ""
    client_id = FLAAT_CLIENT_ID
    client_secret = FLAAT_CLIENT_SECRET
    access_token = []
    oidc_agent_account = ""
    show_access_token = False
    show_user_info = False
    show_introspection_info = False
    show_all = True
    machine_readable = False
    verify_tls = False
    skip_jwt_verify = False
    audience = None
    trust_any = True

    def parse_args(self):
        return self


@pytest.fixture
def args():
    return ArgsMock()


def test_print_infos(args):
    flaat = BaseFlaat()
    flaat.set_trusted_OP_list([FLAAT_ISS])
    user_infos = flaat.get_user_infos_from_access_token(FLAAT_AT)
    printer = UserInfosPrinter(user_infos)

    printer.print(args)

    args.machine_readable = True
    printer.print(args)


def test_get_flaat():
    trusted_op_list = TRUSTED_OP_LIST[:1]
    assert get_flaat(ArgsMock(), trusted_op_list) is not None


def test_get_at_environment_oidc_agent(args, monkeypatch):
    if OIDC_AGENT_ACCOUNT == "":
        pytest.skip("No oidc agent")
    monkeypatch.setenv("OIDC_AGENT_ACCOUNT", OIDC_AGENT_ACCOUNT)
    assert get_access_token(args) == FLAAT_AT


def test_get_at_environment_access_token(args, monkeypatch):
    monkeypatch.delenv("OIDC_AGENT_ACCOUNT", raising=False)
    monkeypatch.setenv("ACCESS_TOKEN", "bar")
    assert get_access_token(args) == "bar"


def test_get_at_oidc_agent(args):
    if OIDC_AGENT_ACCOUNT == "":
        pytest.skip("No oidc agent")
    args.oidc_agent_account = OIDC_AGENT_ACCOUNT
    assert get_access_token(args) == FLAAT_AT


def test_get_at_access_token(args):
    args.access_token = ["foo"]
    assert get_access_token(args) == "foo"


def test_get_at_oidc_agent_with_aud(args):
    if AUD_OIDC_AGENT_ACCOUNT == "":
        pytest.skip("No oidc agent account for OP with audience")
    args.oidc_agent_account = AUD_OIDC_AGENT_ACCOUNT
    args.audience = "test-audience"

    at = get_access_token(args)
    assert at is not None

    unverified = decode_complete(at, options={"verify_signature": False})
    assert unverified["payload"]["aud"] == "test-audience"


def test_main(args, monkeypatch):
    monkeypatch.delenv("OIDC_AGENT_ACCOUNT", raising=False)
    monkeypatch.setenv("ACCESS_TOKEN", FLAAT_AT)
    monkeypatch.setattr(flaat_userinfo, "get_arg_parser", lambda: args)
    monkeypatch.setattr(flaat_userinfo, "TRUSTED_OP_LIST", [FLAAT_ISS])
    main()
