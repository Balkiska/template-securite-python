### API key

The Gemini API free tier is not available in the EU/France — Google blocks it due to GDPR regulations. Every key i tried to created like in class had a 0 limit, meaning 0 requests allowed, not even exceeded a quota.
-> I decided to take a groq API key. I will not push it on github (croped it) but here is the output of the tp2 i the file output.txt




### Had to create a nex exegol container with a new image for pylibemu

execution:
docker run -it --rm -v $(pwd):/tp ubuntu:22.04 bash

apt-get update && apt-get install -y git autoconf libtool build-essential python3 python3-pip


git clone https://github.com/buffer/libemu.git
cd libemu && autoreconf -v -i && ./configure && make && make install && ldconfig


pip3 install pylibemu capstone requests python-dotenv

pip3 install pylibemu capstone requests python-dotenv

PYTHONPATH=/tp/src:/tp python3 /tp/src/tp2/main.py -f /tp/shellcode.txt
