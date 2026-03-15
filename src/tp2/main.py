import argparse
import os

from tp2.utils.config import logger
from tp2.utils.lib import get_capstone_analysis, get_llm_analysis, get_pylibemu_analysis, get_shellcode_strings


def _load_shellcode(path: str) -> bytes:
    """Read shellcode file: raw bytes or \\xNN escape-sequence text."""
    with open(path, "rb") as f:
        raw = f.read().strip()
    if b"\\x" in raw:
        return raw.decode("unicode_escape").encode("latin-1")
    return raw


def main():
    parser = argparse.ArgumentParser(description="TP2 - Shellcode analyser")
    parser.add_argument("-f", "--file", required=True, help="Path to shellcode file")
    args = parser.parse_args()

    shellcode = _load_shellcode(args.file)
    logger.info(f"Testing shellcode of size {len(shellcode)}B")

    strings = get_shellcode_strings(shellcode)
    capstone = get_capstone_analysis(shellcode)
    pylibemu = get_pylibemu_analysis(shellcode)

    logger.info(f"Shellcode analysed!\n{pylibemu}")
    logger.info(f"Shellcode instructions:\n{capstone}")

    analysis = get_llm_analysis(strings, capstone, pylibemu, os.getenv("MYFABULOUS_KEY", ""))
    logger.info(f"Explication LLM : {analysis}")


if __name__ == "__main__":
    main()
