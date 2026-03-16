from io import BytesIO

import pytesseract
import requests
from PIL import Image


class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = ""
        self.value = ""
        self.session = requests.Session()

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        self.session.get(self.url)
        resp = self.session.get(self.url + "../captcha.php")
        self.image = Image.open(BytesIO(resp.content))

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        self.value = pytesseract.image_to_string(self.image, config="--psm 7 digits").strip()

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
