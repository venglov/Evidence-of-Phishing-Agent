def extract_argument(event: dict, argument: str) -> any:
    """
    the function extract specified argument from the event
    :param event: dict
    :param argument: str
    :return: argument value
    """
    return event.get('args', {}).get(argument, "")


def is_EOA(address: str, w3) -> bool:
    """
    The functions checks if the address is EOA
    :param address:
    :param w3:
    :return: bool
    """
    return w3.eth.getCode(address) == '0x'
