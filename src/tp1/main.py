import argparse
from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    parser = argparse.ArgumentParser(description="TP1 — IDS/IPS Maison")
    parser.add_argument("--interface", "-i", type=str, default=None, help="Network interface (skip prompt)")
    parser.add_argument("--timeout", "-t", type=int, default=30, help="capture timeout in seconds (default: 30)")
    parser.add_argument("--count", "-c", type=int, default=50, help="Max packets to capture (default: 50)")
    parser.add_argument("--output", "-o", type=str, default="report.pdf", help="Output PDF filename (default: report.pdf)")
    args = parser.parse_args()

    logger.info("Starting TP1 — IDS/IPS Maison")

    # cpture
    capture = Capture(interface=args.interface, count=args.count, timeout=args.timeout)
    capture.capture_traffic()

    # analyse
    capture.analyse("all")
    summary = capture.get_summary()
    logger.info(f"\n{summary}")

    # aeport
    report = Report(capture, args.output, summary)
    report.generate("graph")
    report.generate("array")
    report.save(args.output)

    logger.info(f"Done! Report saved to {args.output}")


if __name__ == "__main__":
    main()
