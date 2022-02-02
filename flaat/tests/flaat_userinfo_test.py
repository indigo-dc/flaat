from dataclasses import dataclass
from flaat import BaseFlaat
from flaat.flaat_userinfo import PrintableUserInfos, get_access_token, get_flaat
from flaat.test_env import FLAAT_AT, FLAAT_ISS, OIDC_AGENT_ACCOUNT


@dataclass
class ArgsMock:
    verbose = 3
    client_id = ""
    client_secret = ""
    access_token = []
    oidc_agent_account = ""
    show_access_token = False
    show_user_info = False
    show_introspection_info = False
    show_all = False
    machine_readable = False


def test_print_infos():
    flaat = BaseFlaat()
    flaat.set_trusted_OP_list([FLAAT_ISS])
    infos = PrintableUserInfos(flaat, FLAAT_AT)
    assert infos is not None

    args = ArgsMock()
    args.show_all = True
    infos.print(args)

    args.machine_readable = True
    infos.print(args)


def test_get_flaat():
    assert get_flaat(ArgsMock()) is not None


def test_get_at():
    args = ArgsMock()
    # from environment
    assert get_access_token(args) == FLAAT_AT

    args.oidc_agent_account = OIDC_AGENT_ACCOUNT
    assert get_access_token(args) == FLAAT_AT

    args.access_token = ["foo"]
    assert get_access_token(args) == "foo"
