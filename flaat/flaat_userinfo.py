#!/usr/bin/env python3

import json
import logging
import os
import sys
from typing import Optional

import configargparse
import liboidcagent as agent
from humanfriendly import format_timespan

from flaat import BaseFlaat
from flaat.exceptions import FlaatException
from flaat.user_infos import UserInfos
from flaat.access_tokens import get_access_token_info

logger = logging.getLogger(__name__)

TRUSTED_OP_LIST = [
    "https://b2access.eudat.eu/oauth2/",
    "https://b2access-integration.fz-juelich.de/oauth2",
    "https://unity.helmholtz-data-federation.de/oauth2/",
    "https://login.helmholtz-data-federation.de/oauth2/",
    "https://login-dev.helmholtz.de/oauth2/",
    "https://login.helmholtz.de/oauth2/",
    "https://unity.eudat-aai.fz-juelich.de/oauth2/",
    "https://services.humanbrainproject.eu/oidc/",
    "https://accounts.google.com/",
    "https://aai.egi.eu/oidc/",
    "https://aai.egi.eu/auth/realms/egi",
    "https://aai-demo.egi.eu/auth/realms/egi",
    "https://aai-demo.egi.eu/oidc/",
    "https://aai-dev.egi.eu/oidc/",
    "https://aai-dev.egi.eu/auth/realms/egi",
    "https://login.elixir-czech.org/oidc/",
    "https://iam-test.indigo-datacloud.eu/",
    "https://iam.deep-hybrid-datacloud.eu/",
    "https://iam.extreme-datacloud.eu/",
    "https://oidc.scc.kit.edu/auth/realms/kit/",
    "https://proxy.demo.eduteams.org",
    "https://wlcg.cloud.cnaf.infn.it/",
    "https://proxy.eduteams.org/",
    "https://proxy.eduteams.org/",
    "https://regapp.nfdi-aai.de/oidc/realms/nfdi_demo",
    "https://auth.didmos.nfdi-aai.de",
    "https://cilogon.org/",
    "https://keycloak.sso.gwdg.de/auth/realms/academiccloud",
]


def get_arg_parser():  # pragma: no cover
    path_of_executable = os.path.realpath(sys.argv[0])
    folder_of_executable = os.path.split(path_of_executable)[0]
    full_name_of_executable = os.path.split(path_of_executable)[1]
    name_of_executable = full_name_of_executable.rstrip(".py")

    config_files = [
        f"{os.environ['HOME']}/.config/{name_of_executable}conf",
        f"{folder_of_executable}/{name_of_executable}.conf",
        f"/root/configs/{name_of_executable}.conf",
    ]
    parser = configargparse.ArgumentParser(
        default_config_files=config_files,
        description=name_of_executable,
        ignore_unknown_config_file_keys=True,
    )

    # Arguments below
    parser.add_argument(
        "--my-config",
        "-c",
        is_config_file=True,
        help="config file path",
    )
    parser.add_argument(
        "--client_id",
        default="",
        help="Specify the client_id of an oidc client. This is needed for token introspection.",
    )
    parser.add_argument(
        "--client_secret",
        default="",
        help="Specify the client_secret of an oidc client. This is may be needed for token introspection.",
    )
    parser.add_argument(
        "--oidc-agent-account",
        "-o",
        default="",
        help="Name of oidc-agent account for access token retrieval",
    )
    parser.add_argument(
        "--issuer",
        "-i",
        default="",
        help="Specify issuer (OIDC Provider)",
    )
    parser.add_argument(
        "--audience",
        "--aud",
        default=None,
        help=(
            "Specify an intended audience for the requested access token. "
            "Multiple audiences can be provided as a space separated list. "
            "Only used when token is retrieved via the oidc-agent. "
            "Ignored if OP does not support audience setting."
        ),
    )

    # FLAGS below
    parser.add_argument(
        "--skip_tls_verify",
        default=True,
        action="store_false",
        help="Disable TLS verification",
    )
    parser.add_argument(
        "--skip_jwt_verify",
        default=False,
        action="store_true",
        help="Disable JWT verification",
    )

    parser.add_argument(
        "--accesstoken",
        "-at",
        default=False,
        action="store_true",
        dest="show_access_token",
        help="Show access token info (default)",
    )
    parser.add_argument(
        "--userinfo",
        "-ui",
        default=False,
        action="store_true",
        dest="show_user_info",
        help="Show user info (default)",
    )
    parser.add_argument(
        "--introspection",
        "-in",
        default=False,
        action="store_true",
        dest="show_introspection_info",
        help="Show introspection info (default)",
    )
    parser.add_argument(
        "--all",
        "-a",
        default=True,
        action="store_false",
        dest="show_all",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        default=False,
        action="store_true",
        help="Enable quiet mode. This will only show requested information, no explanatory text",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        dest="verbose",
        help="Enable verbose mode. This will also print debug messages.",
    )
    parser.add_argument(
        "--machine-readable",
        "-m",
        default=False,
        action="store_true",
        dest="machine_readable",
        help="Make stdout machine readable",
    )
    parser.add_argument(
        dest="access_token",
        default=None,
        nargs="*",
        help="An access token (without 'Bearer ')",
    )
    parser.add_argument(
        "--trust-any",
        "--any",
        action="store_true",
        default=True,
        dest="trust_any",
        help="Trust any OP, usefule for displaying information about any access_token",
    )
    return parser


def get_args():
    parser = get_arg_parser()
    args = parser.parse_args()
    # if -in -ui or -at are specified, we set all to false:
    if args.show_user_info or args.show_access_token or args.show_introspection_info:
        args.show_all = False
    return args


def get_flaat(args, trusted_op_list=None):
    flaat = BaseFlaat()

    verbosity = 2  # info
    # quiet has precedence over verbose
    if args.quiet:
        verbosity = 1  # warn
    elif args.verbose:
        verbosity = 3  # debug
    flaat.set_verbosity(verbosity, set_global=True)

    # Log to stderr
    handler = logging.StreamHandler(sys.stderr)
    root = logging.getLogger()
    root.addHandler(handler)

    if trusted_op_list is not None:
        flaat.set_trusted_OP_list(trusted_op_list)
    else:
        flaat.set_trusted_OP_list(TRUSTED_OP_LIST)
    if args.client_id:
        flaat.set_client_id(args.client_id)
    if args.client_secret:
        flaat.set_client_secret(args.client_secret)
    if args.skip_jwt_verify:
        flaat.set_verify_jwt(not args.skip_jwt_verify)
    return flaat


def get_access_token(args) -> Optional[str]:
    access_token = None
    if isinstance(args.access_token, list) and len(args.access_token) > 0:
        # use only the first one for now:
        access_token = args.access_token[0]
        if access_token is not None:
            logger.info("Using access token from commandline")
            return access_token

    # try commandline
    if args.oidc_agent_account != "":
        try:
            access_token = agent.get_access_token(
                args.oidc_agent_account, audience=args.audience
            )
        except agent.OidcAgentError as e:
            raise FlaatException(
                f"Could not use oidc-agent account '{args.oidc_agent_account}': {e}"
            ) from e

        if access_token is not None:
            logger.info(
                "Using access token from oidc-agent (account specified via commandline)"
            )
            return access_token
        raise FlaatException("Access token from oidc-agent is none")

    # try environment  for config
    env_vars_to_try = ["OIDC_AGENT_ACCOUNT"]
    for env_var in env_vars_to_try:
        account_name = os.getenv(env_var)
        if account_name is not None:
            logger.debug("Using agent account '%s'", env_var)
            try:
                access_token = agent.get_access_token(
                    account_name, audience=args.audience
                )
                if access_token is not None:
                    logger.info(
                        "Using access token from oidc-agent (from environment variable '%s')",
                        env_var,
                    )
                    return access_token
            except agent.OidcAgentError as e:
                logger.warning("Could not use oidc-agent: %s", e)

    # try environment for Access Token:
    env_vars_to_try = [
        "ACCESS_TOKEN",
        "OIDC",
        "OS_ACCESS_TOKEN",
        "OIDC_ACCESS_TOKEN",
        "WATTS_TOKEN",
        "WATTSON_TOKEN",
    ]
    for env_var in env_vars_to_try:
        access_token = os.getenv(env_var)
        if access_token is not None:
            logger.info("Using access token from environment variable '%s'", env_var)
            return access_token

    return access_token


class UserInfosPrinter:
    def __init__(self, user_infos: Optional[UserInfos]):
        self.user_infos = user_infos

    def print(self, args):
        if args.machine_readable:
            self.print_machine_readable()
        else:
            self.print_human_readable(args)

    def print_machine_readable(self):
        if self.user_infos is None:
            error = {"error": "No user infos found"}
            print(json.dumps(error))
            sys.exit(2)

        print(self.user_infos.toJSON())

    @staticmethod
    def print_json(content):
        print(
            json.dumps(
                content,
                sort_keys=True,
                indent=4,
                separators=(",", ": "),
            )
        )

    def print_human_readable(self, args):
        if self.user_infos is None:
            logger.error("Error: No user infos found")
            sys.exit(2)

        if args.show_access_token or args.show_all:
            if self.user_infos.access_token_info is None:
                logger.warning("Your access token is not a JWT")
            else:
                logger.info("Information stored inside the access token:")
                self.print_json(self.user_infos.access_token_info.__dict__)
            print("")

        if args.show_user_info or args.show_all:
            logger.info("Information retrieved from userinfo endpoint:")
            self.print_json(self.user_infos.user_info)
            print("")

        if args.show_introspection_info or args.show_all:
            if self.user_infos.introspection_info is None:
                if args.client_id != "":
                    logger.warning(
                        """Error retrieving token introspection info
            Submit an issue at https://github.com/indigo-dc/flaat if you feel this is wrong"""
                    )
            else:
                logger.info("Information retrieved from introspection endpoint:")
                self.print_json(self.user_infos.introspection_info)
            print("")

        if self.user_infos.valid_for_secs is not None:
            logger.info(
                "Your token is valid for %s."
                if self.user_infos.valid_for_secs > 0
                else "Your token has EXPIRED for %s!",
                format_timespan(self.user_infos.valid_for_secs),
            )


def main():
    try:
        args = get_args()
        flaat = get_flaat(args)
        access_token = get_access_token(args)
        if access_token is None:
            logger.error("No access token found")
            sys.exit(1)
        if args.trust_any:
            at_info = get_access_token_info(access_token)
            if at_info and hasattr(at_info, "body"):
                flaat.set_trusted_OP_list([at_info.body["iss"]])
        user_infos = flaat.get_user_infos_from_access_token(
            access_token, issuer_hint=args.issuer
        )
        UserInfosPrinter(user_infos).print(args)
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Error: %s", e)
        sys.exit(3)


if __name__ == "__main__":
    main()
