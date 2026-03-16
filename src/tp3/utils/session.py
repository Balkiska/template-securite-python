import random

from src.tp3.utils.captcha import Captcha


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.response = None
        self.captcha_session = None

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.captcha_session = captcha.session
        self.flag_value = str(random.randint(1000, 2000))

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        data = {"flag": self.flag_value, "captcha": self.captcha_value, "submit": "submit"}
        self.response = self.captcha_session.post(self.url, data=data)

    def process_response(self):
        """
        Processes the response.
        """
        if "Invalid captcha" not in self.response.text:
            self.valid_flag = self.flag_value
            return True
        return False

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
