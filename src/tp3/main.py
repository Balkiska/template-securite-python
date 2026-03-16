from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3")

    ip = "31.220.95.27:9002"
    challenges = {"1": f"http://{ip}/captcha1/"}

    for i in challenges:
        url = challenges[i]
        session = Session(url)
        session.prepare_request()
        session.submit_request()

        while not session.process_response():
            session.prepare_request()
            session.submit_request()

        logger.info("Smell good !")
        print(f"\033[38;2;255;182;193m Flag for {url} : {session.get_flag()} \033[0m")


if __name__ == "__main__":
    main()
