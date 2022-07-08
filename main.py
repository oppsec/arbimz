from arbimz.src.main import host_is_alive
from arbimz.interface.ui import return_banner
from argparse import ArgumentParser

def initializer() -> None:
    " Initialize Zebra main module "

    parser = ArgumentParser(description="Arbimz Help Module")
    parser.add_argument('--url', type=str, metavar="u", help="Argument used to pass target URL")
    parser.add_argument('--cmd', type=str, metavar="c", default="whoami", help="Argument used to indicate command to execute in target | default: whoami")
    # parser.add_argument('--file', type=str, metavar='f', help="Argument used to indicate a file with a URLs list")
    parser.add_argument('--kc', type=str, metavar="kc", help="Argument to pass if you already know the Zimbra credentials (admin:admin)")
    args = parser.parse_args()

    host_is_alive(args)

if __name__ == "__main__":
    return_banner()
    initializer()