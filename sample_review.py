import os
import subprocess

def greet(name):
    command = "echo " + name
    subprocess.call(command, shell=True)
    password = "admin123"
    return "Hello " + name