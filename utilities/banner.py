from colorama import Fore, Style


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + """
     █████╗ ██████╗ ██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗
    ██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
    ███████║██████╔╝██████╔╝    ███████╗██████╔╝██║   ██║██║   ██║█████╗  
    ██╔══██║██╔══██╗██╔═══╝     ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  
    ██║  ██║██║  ██║██║         ███████║██║     ╚██████╔╝╚██████╔╝██║     
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     
        Github: https://github.com/SaherMuhamed/arp-spoofing-mitm
    """ + Style.RESET_ALL + Fore.YELLOW + Style.BRIGHT + "\t\t  By Saher Muhamed - version 2.1.1" + Style.RESET_ALL)
    print(
        Fore.YELLOW + Style.BRIGHT + "──────────────────────────────────────────────────────────────────────────" +
        Style.RESET_ALL)
