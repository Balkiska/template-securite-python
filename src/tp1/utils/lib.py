from scapy.all import get_if_list


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    List available network interfaces and let the user pick one.

    :return: selected network interface name
    """
    interfaces = get_if_list()
    if not interfaces:
        return ""

    print("\nAvailable Network Interfaces")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")
    print()

    while True:
        try:
            choice = int(input("Select interface number: "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            print(f"Please enter a number between 0 and {len(interfaces) - 1}")
        except (ValueError, EOFError):
            return interfaces[0]
