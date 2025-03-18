from utils import hybridEncrypt
from argparse import ArgumentParser

if __name__ == "__main__":
  parser = ArgumentParser(description="Encrypt a file using a symmetric key encrypted with a public RSA key.")
  parser.add_argument("--receiver_pub_key", required=True, help="Path to the receiver's public key file.")
  parser.add_argument("--input_file", required=True, help="Path to the input file to encrypt.")
  parser.add_argument("--output_encrypted_file", required=True, help="Path to save the encrypted file.")
  parser.add_argument("--output_encrypted_symmetric_key", required=True, help="Path to save the encrypted symmetric key.")

  args = parser.parse_args()
  hybridEncrypt(args.receiver_pub_key, args.input_file, args.output_encrypted_file, args.output_encrypted_symmetric_key)