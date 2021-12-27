import pathlib
import struct
import time
import secrets
import PySimpleGUI as sg
import hashlib


class PasswordStore:

    def generate_salt(self, byte_len=64):
        return secrets.token_urlsafe(byte_len)

    def sha_with_salt(self, digest_mod, password, salt=generate_salt(64)):
        return digest_mod((password + salt).encode()).hexdigest()


class HMAC:

    def __init__(self, key: bytes, message=None, digest_mod=None):

        if callable(digest_mod):
            self.messageDigest = digest_mod

        self.input = self.messageDigest()
        self.output = self.messageDigest()

        self.block_size = self.input.block_size
        if len(key) > self.block_size:
            key = self.messageDigest(key).digest()

        key = key.ljust(self.block_size, b'\0')

        self.ipad = 0x36  # = 00110110
        self.input_signature = bytes((K ^ self.ipad) for K in key)
        self.opad = 0x5C  # = 01011100
        self.output_signature = bytes((K ^ self.opad) for K in key)

        self.input.update(self.input_signature)
        self.output.update(self.output_signature)

        if message is not None:
            self.input.update(message)

    def hexdigest(self):
        h = self.output.copy()
        h.update(self.input.digest())
        return h.hexdigest()

    def digest(self):
        h = self.output.copy()
        h.update(self.input.digest())
        return h.digest()


class PBKDF2:

    def __init__(self, digest_mod, master_password, salt, count, dk_length):
        self.digest_mod = digest_mod
        self.password = master_password
        self.salt = salt
        self.count = count
        self.dk_length = dk_length

    def pbkdf2_function(self, passwd, salt, count, i):
        r = u = HMAC(passwd, salt + struct.pack(">i", i), self.digest_mod).digest()
        for i in range(2, count + 1):
            u = HMAC(passwd, u, self.digest_mod).digest()
            r = bytes(i ^ j for i, j in zip(r, u))
        return r

    def result(self):
        dk, h_length = b'', self.digest_mod().digest_size
        blocks = (self.dk_length // h_length) + (1 if self.dk_length % h_length else 0)
        for i in range(1, blocks + 1):
            dk += self.pbkdf2_function(self.password, self.salt, self.count, i)
        return dk[:self.dk_length].hex()


def start_gui():
    layout = [
        [
            sg.Text('Tip'),
            sg.Radio("SHA256", "HashType", default=True, key='_sha256_type_'),
            sg.Radio("SHA512", "HashType", default=False, key='_sha512_type_'),
        ],
        [
            sg.Text('Način'),
            sg.Radio("Hranjenje gesel (pass + salt)", "Mode", default=True, key='_pass_mode_'),
            sg.Radio("HMAC", "Mode", default=False, key='_hmac_mode_'),
            sg.Radio("PBKDF2", "Mode", default=False, key='_pbkdf2_mode_'),
        ],
        [sg.Text('Sol'), sg.InputText(key='_salt_input_'), sg.Button(button_text='Generiraj sol')],
        [sg.Text('Ključ'), sg.InputText(key='_key_input_'), sg.Button(button_text='Generiraj ključ')],
        [sg.Text('Geslo'), sg.InputText(key='_pass_input_')],
        # [sg.Text('HMAC file'), sg.InputText(key='_file_input_'), sg.FileBrowse('Odpri')],
        [sg.Output(size=(88, 20))],
        [sg.Button(button_text='Hashiraj'), sg.Cancel(button_text='Zapri')]
    ]
    window = sg.Window('Hashing functions', layout)

    counter = 0

    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Cancel', 'Zapri'):
            break
        if event == 'Generiraj sol':
            window['_salt_input_'].Update(secrets.token_urlsafe(32))
        if event == 'Generiraj ključ':
            window['_key_input_'].Update(secrets.token_urlsafe(32))

        if event == 'Submit' or event == 'Hashiraj':
            # filepath = is_validation_ok = None
            # filepath = values['_file_input_']

            try:
                print("------------------------------------------------")
                start_time = time.process_time()

                if values['_pass_mode_']:
                    salt = values['_salt_input_']
                    password = values['_pass_input_']

                    print(f"---- INPUTS salt: {salt}")
                    print(f"---- INPUTS password: {password}")

                    ps = PasswordStore()
                    if values['_sha256_type_']:
                        result = ps.sha_with_salt(hashlib.sha256, password, salt)
                        print("OUTPUT: " + result)
                    elif values['_sha512_type_']:
                        result = ps.sha_with_salt(hashlib.sha512, password, salt)
                        print("OUTPUT: " + result)

                    with open(str(pathlib.Path().absolute()) + f"/salt-{counter}.txt", "w") as salt_file:
                        salt_file.write(salt)

                    with open(str(pathlib.Path().absolute()) + f"/hashed_pass-{counter}.txt", "w") as hashed_pass_file:
                        hashed_pass_file.write(result)

                    print("--- End hashing ---")
                    counter += 1

                elif values['_hmac_mode_']:
                    key = bytes(values['_key_input_'], 'utf-8')
                    password = bytes(values['_pass_input_'], 'utf-8')

                    print(f"---- INPUTS key: {key}")
                    print(f"---- INPUTS password: {password}")

                    if values['_sha256_type_']:
                        r = HMAC(key, password, hashlib.sha256)
                        print("OUTPUT: " + r.hexdigest())
                    elif values['_sha512_type_']:
                        r = HMAC(key, password, hashlib.sha512)
                        print("OUTPUT: " + r.hexdigest())

                    print("--- End HMAC ---")

                elif values['_pbkdf2_mode_']:
                    salt = bytes(values['_salt_input_'], 'utf-8')
                    password = bytes(values['_pass_input_'], 'utf-8')

                    print(f"---- INPUTS salt: {salt}")
                    print(f"---- INPUTS password: {password}")

                    if values['_sha256_type_']:
                        pbkdf2 = PBKDF2(hashlib.sha256, password, salt, 31000, 32)
                        print("OUTPUT: " + pbkdf2.result())
                    elif values['_sha512_type_']:
                        pbkdf2 = PBKDF2(hashlib.sha512, password, salt, 12000, 64)
                        print("OUTPUT: " + pbkdf2.result())

                    print("--- End PBKDF2 ---")

                print("------------------------------------------------")

            except:
                print('*** Napaka v procesu hashiranja ***')
    window.close()


if __name__ == '__main__':
    start_gui()
