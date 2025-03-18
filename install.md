## How to run the code

- Set the working directory the source code directory: cd ./src
- Install dependencies: pip install argparse pycryptodome , or pip install -r requirements.txt
- As the private and public keys have to be in PEM format, we can use utils.py to generate a public key file and a private key file, for example (--key_size is optional): python utils.py --public_key file_name_or_path_of_public_key.pub --private_key file_name_or_path_of_private_key.key --key_size 2048
- After that, you can use encryptor.py and decryptor.py like in the lab description.