# PYTHON ENCRYPTION

This project shows how to start with encryption in Python using cryptography module and maximizing hazmat to use RSA to sign, verify, encrypt and decrypt text or data.

## Requirements
* [Python 3.8.1](https://www.python.org/downloads/release/python-381)
* [Package Manager](https://pip.pypa.io/en/stable/)

## Installation
* Create a virtual environment
```bash
python3 -m venv venv
```
* Enable the virtualenvironment
```bash
source venv/bin/activate
```
* Install libraries
```bash
pip install -r requirements.txt
```

## Usage
* Running the script
```bash
# This will generate private and public key file to be used
python main.py
```
* Running the test cases
```bash
cd tests
pytest -v test.py 
```
* Run Encrypt Text
```bash
python encrypt.py 
```
* Run Decrypt Text
```bash
python decrypt.py 
```

