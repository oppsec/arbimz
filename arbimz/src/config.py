from random import randint


def get_user_agent() -> str:
    " Return a random User-Agent from user-agents.txt file to use in request "

    path: str = "arbimz/data/user-agents.txt"
    with open(path) as file:
        user_agent = file.readlines()
        user_agent = user_agent[randint(0, len(user_agent) -1)]
        user_agent = user_agent.encode('utf-8')

        return str(user_agent)

headers = {
    "User-Agent": get_user_agent(),
    "Connection": "keep-alive"
}

props = {
    'verify': False,
    'allow_redirects': True,
    'headers': headers
}