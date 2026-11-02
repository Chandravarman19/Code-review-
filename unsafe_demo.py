import subprocess
import random
import tempfile

def run_command(user_input):
    return subprocess.call(user_input, shell=True)

def make_token():
    return str(random.random())

def create_temp_file():
    return tempfile.mktemp()