from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import argparse

def decrypt_file(input_path, output_path, password, salt, iterations=1000):
    # 入力ファイルをバイナリモードで読み込み
    with open(input_path, "rb") as f:
        encrypted_data = f.read()

    # PBKDF2で32バイト（鍵16バイト＋IV16バイト）のデータを導出
    derived = PBKDF2(password, salt, dkLen=32, count=iterations)
    key = derived[:16]
    iv = derived[16:]

    # AES-CBC モードで復号化
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data)

    # PKCS7 パディングの除去
    pad_len = decrypted[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("不正なパディング値です")
    decrypted = decrypted[:-pad_len]

    # 復号化したデータを出力ファイルに書き込み
    with open(output_path, "wb") as f:
        f.write(decrypted)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AES-CBC でファイルを復号化します")
    parser.add_argument("input", help="暗号化された入力ファイルのパス")
    parser.add_argument("output", help="復号化した出力ファイルのパス")
    parser.add_argument("--password", default="u8DurGE2", help="復号用パスワード")
    parser.add_argument("--salt", default="6BBGizHE", help="鍵導出用ソルト")
    args = parser.parse_args()

    # ソルトはバイト列で渡すため、UTF-8でエンコード
    decrypt_file(args.input, args.output, args.password, args.salt.encode('utf-8'))
