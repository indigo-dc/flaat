from dataclasses import dataclass
from flaat import BaseFlaat
from flaat.flaat_userinfo import (
    TRUSTED_OP_LIST,
    UserInfosPrinter,
    get_access_token,
    get_flaat,
)
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
    user_infos = flaat.get_user_infos_from_access_token(FLAAT_AT)
    printer = UserInfosPrinter(user_infos)

    args = ArgsMock()
    args.show_all = True
    printer.print(args)

    args.machine_readable = True
    printer.print(args)


def test_get_flaat():
    trusted_op_list = TRUSTED_OP_LIST[:1]
    assert get_flaat(ArgsMock(), trusted_op_list) is not None


def test_get_at():
    args = ArgsMock()
    # from environment
    assert get_access_token(args) == FLAAT_AT

    args.oidc_agent_account = OIDC_AGENT_ACCOUNT
    assert get_access_token(args) == FLAAT_AT

    args.access_token = ["foo"]
    assert get_access_token(args) == "foo"
