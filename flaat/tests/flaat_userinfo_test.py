from flaat import BaseFlaat
from flaat.flaat_userinfo import PrintableUserInfos
from flaat.test_env import FLAAT_AT, FLAAT_ISS


def test_infos_machine_readable():
    flaat = BaseFlaat()
    flaat.set_trusted_OP_list([FLAAT_ISS])
    infos = PrintableUserInfos(flaat, FLAAT_AT)
    assert infos is not None
    infos.print_machine_readable()


def test_infos_human_readable():
    flaat = BaseFlaat()
    flaat.set_trusted_OP_list([FLAAT_ISS])
    infos = PrintableUserInfos(flaat, FLAAT_AT)
    assert infos is not None
    infos.print_machine_readable()
