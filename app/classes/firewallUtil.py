import os


def print_brk():
    print('-' * os.get_terminal_size().columns)


def input_ip_sequence(prompt: str) -> str:
    ip_to_add = input(prompt)
    valid_input = True if ip_to_add[:2] == "0x" else False
    while not valid_input:
        ip_to_add = input("Invalid input, please enter a valid IP (e.g., 0x1A).\n> ")
        valid_input = True if ip_to_add[:2] == "0x" else False

    return ip_to_add
