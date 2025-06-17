import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

class Colors:
    @staticmethod
    def red(str):
        return Fore.RED + str + Style.RESET_ALL
    
    @staticmethod
    def green(str):
        return Fore.GREEN + str + Style.RESET_ALL
    
    @staticmethod
    def yellow(str):
        return Fore.YELLOW + str + Style.RESET_ALL
    
    @staticmethod
    def blue(str):
        return Fore.BLUE + str + Style.RESET_ALL
    
    @staticmethod
    def magenta(str):
        return Fore.MAGENTA + str + Style.RESET_ALL
    
    @staticmethod
    def cyan(str):
        return Fore.CYAN + str + Style.RESET_ALL
    
    @staticmethod
    def white(str):
        return Fore.WHITE + str + Style.RESET_ALL
    
    @staticmethod
    def black(str):
        return Fore.BLACK + str + Style.RESET_ALL
    
    @staticmethod
    def light_red(str):
        return Fore.LIGHTRED_EX + str + Style.RESET_ALL
    
    @staticmethod
    def light_green(str):
        return Fore.LIGHTGREEN_EX + str + Style.RESET_ALL
    
    @staticmethod
    def light_yellow(str):
        return Fore.LIGHTYELLOW_EX + str + Style.RESET_ALL

    @staticmethod
    def light_blue(str):
        return Fore.LIGHTBLUE_EX + str + Style.RESET_ALL
    
    @staticmethod
    def light_magenta(str):
        return Fore.LIGHTMAGENTA_EX + str + Style.RESET_ALL
        
    
def banner():
    print(Colors.light_red("""
          

 ▄████▄  ▄▄▄█████▓  █████▒██▓███   ▄▄▄       ▄████▄   ██ ▄█▀▓█████  ██▀███  
▒██▀ ▀█  ▓  ██▒ ▓▒▓██   ▒▓██░  ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄ ▒ ▓██░ ▒░▒████ ░▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ ▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒░ ▓██▓ ░ ░▓█▒  ░▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  
▒ ▓███▀ ░  ▒██▒ ░ ░▒█░   ▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░  ▒ ░░    ▒ ░   ▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒       ░     ░     ░▒ ░       ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░
░          ░       ░ ░   ░░         ░   ▒   ░        ░ ░░ ░    ░     ░░   ░ 
░ ░                                     ░  ░░ ░      ░  ░      ░  ░   ░     
░                                           ░                               

                                                                  
    """)+
    ("\n\tAuthor: mocha") +("\n\thttps://mochabyte.xyz\n"))