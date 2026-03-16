import base64

from pwn import remote

from tp4.utils.config import logger

SERVER_IP = "31.220.95.27"
SERVER_PORT = 13337

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9",
}


def try_decode(func, challenge):
    try:
        return func(challenge)
    except:
        return None


def decode_morse(text):
    return "".join(MORSE[c] for c in text.split())


def decode(challenge):

    # Morse
    if set(challenge) <= {".", "-", " "}:
        return decode_morse(challenge)

    decoders = [
        lambda x: bytes.fromhex(x).decode(),
        lambda x: base64.b64decode(x + "==").decode(),
        lambda x: base64.b32decode(x + "=" * ((8 - len(x) % 8) % 8)).decode(),
    ]

    for decoder in decoders:
        result = try_decode(decoder, challenge)
        if result:
            return result

    return challenge


def main():
    logger.info("Starting TP4")

    conn = remote(SERVER_IP, SERVER_PORT)

    line = conn.recvline().decode().strip()
    challenge = line.split(": ", 1)[1]

    while True:
        decoded = decode(challenge)

        logger.info(f"Challenge: {challenge}")
        logger.info(f"Decoded: {decoded}")

        conn.sendline(decoded.lower().encode())

        response = conn.recvline().decode().strip()

        if "suivant" not in response.lower():
            print(f"\033[38;2;255;182;193m {response} \033[0m")
            break

        line = conn.recvline().decode().strip()
        challenge = line.split(": ", 1)[1]

    conn.close()


if __name__ == "__main__":
    main()



# def decode(challenge: str) -> str:
#     if " " in challenge:
#         return "".join(MORSE.get(c, "?") for c in challenge.split())
#     try:
#         return bytes.fromhex(challenge).decode()
#     except ValueError:
#         return base64.b64decode(challenge + "==").decode()
