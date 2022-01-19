#!/usr/bin/env python3

import json
import os
import sys

import configargparse
import liboidcagent as agent

from flaat import BaseFlaat
from flaat.user_infos import UserInfos

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
    "https://aai-demo.egi.eu/oidc/",
    "https://aai-dev.egi.eu/oidc/",
    "https://login.elixir-czech.org/oidc/",
    "https://iam-test.indigo-datacloud.eu/",
    "https://iam.deep-hybrid-datacloud.eu/",
    "https://iam.extreme-datacloud.eu/",
    "https://oidc.scc.kit.edu/auth/realms/kit/",
    "https://proxy.demo.eduteams.org",
    "https://wlcg.cloud.cnaf.infn.it/",
]


def get_arg_parser():
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

    parser.add_argument(
        "--my-config", "-c", is_config_file=True, help="config file path"
    )
    parser.add_argument("--verbose", "-v", action="count", default=0, help="Verbosity")
    parser.add_argument("--client_id", default="")
    parser.add_argument("--client_secret", default="")
    parser.add_argument(
        "--verify_tls", default=True, action="store_false", help="disable verify"
    )

    parser.add_argument(
        "--accesstoken",
        "-at",
        default=False,
        action="store_true",
        dest="show_access_token",
    )
    parser.add_argument(
        "--userinfo", "-ui", default=False, action="store_true", dest="show_user_info"
    )
    parser.add_argument(
        "--introspection",
        "-in",
        default=False,
        action="store_true",
        dest="show_introspection_info",
    )
    parser.add_argument(
        "--all", "-a", default=True, action="store_true", dest="show_all"
    )
    parser.add_argument("--quiet", "-q", default=False, action="store_true")
    parser.add_argument(
        "--machine-readable",
        "-m",
        default=False,
        action="store_true",
        dest="machine_readable",
    )

    parser.add_argument("--oidc-agent-account", "--oidc", "--oidc-agent", default=None)

    parser.add_argument(
        "--issuersconf",
        default="/etc/oidc-agent/issuer.config",
        help="issuer.config, e.g. from oidc-agent",
    )
    parser.add_argument(
        "--issuer", "--iss", "-i", help="Specify issuer (OIDC Provider)"
    )
    parser.add_argument(dest="access_token", default=None, nargs="*")
    return parser


def get_args():
    parser = get_arg_parser()
    args = parser.parse_args()
    # if -in -ui or -at are specified, we set all to false:
    if (
        args.show_user_info
        or args.show_access_token
        or args.show_introspection_info
        or args.quiet
    ):
        args.show_all = False
    return args


def get_flaat(args):
    flaat = BaseFlaat()
    flaat.set_verbosity(args.verbose)
    flaat.set_cache_lifetime(300)  # seconds; default is 300
    flaat.set_trusted_OP_list(TRUSTED_OP_LIST)
    if args.client_id:
        flaat.set_client_id(args.client_id)
    if args.client_secret:
        flaat.set_client_secret(args.client_secret)
    return flaat


def get_access_token(args):
    access_token = None
    if isinstance(args.access_token, list) and len(args.access_token) > 0:
        # use only the first one for now:
        access_token = args.access_token[0]
        if access_token is not None and args.verbose > 1:
            print("Using AccessToken from Commandline")
    if access_token is None:
        # try commandline
        if args.oidc_agent_account is not None:
            try:
                access_token = agent.get_access_token(args.oidc_agent_account)
            except agent.OidcAgentError as e:
                print(f"Could not use oidc-agent: {e}")
            if access_token is not None and args.verbose > 1:
                print("Using AccessToken from oidc-agent (specified via commandline)")
    if access_token is None:
        # try environment  for config
        env_vars_to_try = ["OIDC_AGENT_ACCOUNT"]
        for env_var in env_vars_to_try:
            if args.verbose > 2:
                print(f"trying {env_var}")
            account_name = os.getenv(env_var)
            if account_name is not None:
                try:
                    access_token = agent.get_access_token(account_name)
                except agent.OidcAgentError as e:
                    print(f"Could not use oidc-agent: {e}")
                    sys.exit(2)
                if access_token is not None and args.verbose > 1:
                    print(f"Using AccessToken from Environment variable {env_var}")
                if access_token is not None:
                    break
    if access_token is None:
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
            if access_token is not None and args.verbose > 1:
                print(f"Using AccessToken from Environment variable {env_var}")
            if access_token is not None:
                break
    if access_token is None:
        print("No access token found")
        sys.exit(1)
    return access_token


class PrintableUserInfos(UserInfos):
    def print(self, args):
        if args.machine_readable:
            self.print_machine_readable()
        else:
            self.print_human_readable(args)

    def print_machine_readable(self):
        printDict = {}
        for attr_name in [
            "valid_for_secs",
            "access_token_info",
            "user_info",
            "introspection_info",
        ]:
            val = getattr(self, attr_name)
            if val is not None:
                printDict[attr_name] = val

        print(json.dumps(printDict, sort_keys=True, indent=4))

    def print_human_readable(self, args):
        if args.show_access_token or args.show_all:
            if self.access_token_info is None:
                print(
                    "Info: Your access token is not a JWT. I.e. it does not contain information (at least I cannot find it.)"
                )
            else:
                if args.verbose > 0:
                    print(f"verbose: {args.verbose}")
                    print("Information stored inside the access token:")
                print(
                    json.dumps(
                        self.access_token_info,
                        sort_keys=True,
                        indent=4,
                        separators=(",", ": "),
                    )
                )
            print("")
        if args.show_user_info or args.show_all:
            if self.user_info is None:
                print(
                    """The response from the userinfo endpoint does not contain information (at least I cannot find it.)
        Submit an issue at https://github.com/indigo-dc/flaat if you feel this is wrong"""
                )
            else:
                if args.verbose > 0:
                    print("Information retrieved from userinfo endpoint:")
                print(
                    json.dumps(
                        self.user_info, sort_keys=True, indent=4, separators=(",", ": ")
                    )
                )
            print("")

        if args.show_introspection_info:
            if self.introspection_info is None:
                print(
                    """The response from the introspection endpoint does not contain information (at least I cannot find it.)
        Submit an issue at https://github.com/indigo-dc/flaat if you feel this is wrong"""
                )
            else:
                print("Information retrieved from introspection endpoint:")
                print(
                    json.dumps(
                        self.introspection_info,
                        sort_keys=True,
                        indent=4,
                        separators=(",", ": "),
                    )
                )
            print("")

        if self.valid_for_secs > 0:
            print(f"Token valid for {self.valid_for_secs:.1f} more seconds.")
        else:
            print(
                f"Your token is already EXPIRED for {self.valid_for_secs:.1f} seconds!"
            )
        print("")


def main():
    args = get_args()
    flaat = get_flaat(args)
    access_token = get_access_token(args)
    PrintableUserInfos(flaat, access_token).print(args)


if __name__ == "__main__":
    main()
