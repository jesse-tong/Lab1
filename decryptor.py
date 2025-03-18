from utils import hybridDecrypt
from argparse import ArgumentParser

if __name__ == "__main__":
  parser = ArgumentParser(description="Decrypt a file using a symmetric key decrypted with a private RSA key.")
  parser.add_argument("--receiver_private_key", required=True, help="Path to the receiver's private key file.")
  parser.add_argument("--encrypted_key", required=True, help="Path to the encrypted symmetric key file.")
  parser.add_argument("--input_file", required=True, help="Path to the encrypted file to decrypt.")
  parser.add_argument("--output_decrypted_file", required=True, help="Path to save the decrypted file.")

  args = parser.parse_args()
  hashStatus = hybridDecrypt(args.receiver_private_key, args.input_file, args.output_decrypted_file, args.encrypted_key, checkHashSHA256=True)
  if hashStatus is True:
    print("FILE IS VALID")
  elif hashStatus is False:
    print("FILE IS INVALID")