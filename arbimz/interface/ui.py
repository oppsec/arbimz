from rich import print

def return_banner() -> str:
    " Returnt the content from menu file as application banner "

    path: str = "arbimz/interface/menu"
    with open(path) as file:
        content = file.read()
        print(f"[bold cyan on black]{content}[/]")