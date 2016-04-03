import dropbox, shutil, tarfile, datetime, sys
from config import config
from subprocess import call
from tempfile import mkdtemp
from os import path
from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write('Salted__' + salt)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = bs - (len(chunk) % bs)
            chunk += padding_length * chr(padding_length)
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            if padding_length < 1 or padding_length > bs:
               raise ValueError("bad decrypt pad (%d)" % padding_length)
            # all the pad-bytes must be the same
            if chunk[-padding_length:] != (padding_length * chr(padding_length)):
               # this is similar to the bad decrypt:evp_enc.c from openssl program
               raise ValueError("bad decrypt")
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)

date = datetime.date.today().strftime("%d.%m.%Y")
dbx = dropbox.Dropbox(config["ACCESS_TOKEN"])

# now = datetime.datetime.now()
# for entry in dbx.files_list_folder('').entries:
#     delta = now - entry.server_modified
#     print(delta.seconds)
# 
# sys.exit(0)

dir = mkdtemp()
tar_path = path.join(dir, "db.tar.gz")
enc_tar_path = path.join(dir, "db.tar.gz.aes256")
tar = tarfile.open(tar_path, "w:gz")

# print("temp dir: " + dir)

# create dumps and archive them
for db in config["MYSQL_DATABASES"]:
    output = path.join(dir, db + ".sql")

    f = open(output, "w")
    args = [ "mysqldump", "--skip-lock-tables", "--single-transaction",
        "-u", config["MYSQL_USER"],
        "-p" + config["MYSQL_PASSWORD"]
    ]
    if (config["IGNORE_TABLES"]):
        for table in config["IGNORE_TABLES"]:
            args.append("--ignore-table=" + db + "." + table)
    args.append(db)
    call(args, stdout=f)
    f.close()

    if (config["IGNORE_TABLES"]):
        f = open(output, "a")
        args = [ "mysqldump", "--skip-lock-tables", "--single-transaction",
            "-u", config["MYSQL_USER"],
            "-p" + config["MYSQL_PASSWORD"],
            "--no-data", db
        ]
        for table in config["IGNORE_TABLES"]:
            args.append(table)
        call(args, stdout=f)
        f.close()

    tar.add(output, arcname=db + ".sql")

tar.close()

# sys.exit(0)

# encrypt
with open(tar_path, "r") as in_file, open(enc_tar_path, "w") as out_file:
    encrypt(in_file, out_file, config["ENC_PASSWORD"])

# upload to dropbox
with open(enc_tar_path, "r") as in_upload:
    dbx.files_upload(in_upload, "/" + config["NAME_PREFIX"] + date + ".aes", autorename=True)

# decrypt for test
# with open(enc_tar_path, "r") as in_file, open(enc_tar_path + ".tar.gz", "w") as out_file:
#     decrypt(in_file, out_file, config["ENC_PASSWORD"])

shutil.rmtree(dir)
