## How to run the code

- Set the working directory the source code directory: cd ./src
- Install dependencies: pip install argparse pycryptodome , or pip install -r requirements.txt
- As the private and public keys have to be in PEM format, we can use utils.py to generate a public key file and a private key file, for example (--key_size is optional): python utils.py --public_key test_dir/public_key.pub --private_key test_dir/private_key.key --key_size 2048
- After that, you can use encryptor.py and decryptor.py like in the lab description.
- Encryptor example: python encryptor.py --receiver_pub_key test_dir/public_key.pub --input_file test_dir/test_file.txt --output_encrypted_file test_dir/test_file.dat --output_encrypted_symmetric_key test_dir/encrypted_key.key
- Decryptor example: python decryptor.py --receiver_private_key test_dir/private_key.pub --encrypted_key test_dir/encrypted_key.key --input_file test_dir/test_file.dat --output_decrypted_file test_dir/decrypted_test_file.txt