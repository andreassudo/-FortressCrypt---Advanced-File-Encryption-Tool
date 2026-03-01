Encrypt a file (paranoid mode - default) : 

python fortresscrypt.py encrypt secret.pdf

Encrypt with maximum security : 

python fortresscrypt.py encrypt secret.pdf -s maximum --shred

Encrypt with keyfile (2FA) : 

python fortresscrypt.py genkey my.key
python fortresscrypt.py encrypt secret.pdf -k my.key -s paranoid

Decrypt : 

python fortresscrypt.py decrypt secret.pdf.fortress
python fortresscrypt.py decrypt secret.pdf.fortress -k my.key

View file info : 

python fortresscrypt.py info secret.pdf.fortress

Secure file deletion : 

python fortresscrypt.py shred sensitive_file.txt --passes 7

Benchmark : 

python fortresscrypt.py benchmark
