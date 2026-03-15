import string

import requests

from tp2.utils.config import logger


def get_shellcode_strings(shellcode: bytes, min_len: int = 4) -> str:
    """Extract printable ASCII strings from shellcode bytes."""
    printable = set(string.printable) - set("\t\n\r\x0b\x0c")
    result, current = [], []
    for byte in shellcode:
        ch = chr(byte)
        if ch in printable:
            current.append(ch)
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return "\n".join(result)


def get_capstone_analysis(shellcode: bytes) -> str:
    """Disassemble shellcode with Capstone (x86 32-bit)."""
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = [f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}" for i in md.disasm(shellcode, 0x1000)]
    return "\n".join(lines)


def get_pylibemu_analysis(shellcode: bytes) -> str:
    """Emulate shellcode with pylibemu; fallback message if not installed."""
    try:
        import pylibemu

        emulator = pylibemu.Emulator()
        offset = max(0, emulator.shellcode_getpc_test(shellcode))
        emulator.prepare(shellcode, offset)
        emulator.test()
        return emulator.emu_profile_output or "No pylibemu output"
    except ImportError:
        logger.warning("pylibemu not available — skipping emulation")
        return "pylibemu not available (install in Exegol)"


def get_llm_analysis(strings: str, capstone: str, pylibemu: str, api_key: str) -> str:
    """Call Groq API to explain what the shellcode does."""
    if not api_key:
        logger.warning("No key !!!!!! skipping LLM analysis")
        return "No API key provided"
    prompt = (
        "Analyse shellcode and explain in detail what it does.\n\n"
        f"Extracted strings:\n{strings}\n\nDisassembly:\n{capstone}\n\nPylibemu profile:\n{pylibemu}"
    )
    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": "llama-3.1-8b-instant", "messages": [{"role": "user", "content": prompt}]},
        timeout=30,
    )
    return resp.json()["choices"][0]["message"]["content"]
