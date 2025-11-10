from rgbprint import Color
from datetime import datetime

def info(text):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Color(190, 190, 190)}{timestamp} > {Color(127, 127, 127)}INFO{Color(255, 255, 255)} | {text}")

def success(text):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Color(190, 190, 190)}{timestamp} > {Color(0, 255, 0)}SUCCESS{Color(255, 255, 255)} | {text}")

def error(text):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Color(190, 190, 190)}{timestamp} > {Color(255, 0, 0)}ERROR{Color(255, 255, 255)} | {text}")
