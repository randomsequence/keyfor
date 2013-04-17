#KEY FOR __

keyfor - keeps usernames & passwords. Create, Retrieve, Edit Strong Passwords with AES Encryption

Keyfor stores each username & password combination ('key') in a separate encrypted file which can be synced using Dropbox. A master password, stored in your system keyring, is used to encrypt and decrypt your keys.

# SYNPOSIS

    keyfor [add | edit | delete | verify | refresh] [-u <username>] <label>
            all [verify | refresh | list]
            (-h | --help)
            --version

# INSTALL

Latest development version:

 1. Clone the repo: `git clone https://github.com/randomsequence/keyfor.git`
 2. Install: `sudo python setup.py install`

# COMMANDS

## get

    keyfor example.com

What it does:

1. Search your keys directory for a file named `example.com`
2. Search your system keychain for an application password named 'keyfor'. Use your keychain password to decrypt the password
3. Prints your username in bold, and any notes you stored.
4. Copies your password to the clipboard

## add

    keyfor add example.com
    
What it does:    
    
1. Asks you for a username & password, optionally generating a random password
2. Search your system keychain for an application password named 'keyfor'. Use your keychain password to encrypt the username & password
3. Writes the encrypted username and password to text file `example.com`
4. Copies the new password to the clipboard

## edit

    keyfor edit example.com

## delete

    keyfor delete example.com

## verify

    keyfor verify example.com

Verifies that the credentials stored for example.com were encrypted with your keyring password

## refresh

    keyfor refresh example.com

# DEPENDENCIES

* [keyring](https://bitbucket.org/kang/python-keyring-lib)
* [pycrypto](https://www.dlitz.net/software/pycrypto/)
* [docopt](https://github.com/docopt/docopt)

# CONFIGURATION

TBC

#ENCRYPTION

The default encryption in keyfor is AES 256, CBC mode. The encrypted data is a json dump of the username, password and any other information you want to encrypt:

    {
      "username": "mrwalker",
      "password": "secret101"
    }
    

In CBC mode, the encrypted data needs to be a multiple of 16 bytes long. To achieve this the plain text is padded by 1-16 bytes all with a value equal to the number of padding bytes added.

#FILE FORMAT

The encrypted, base-64 encoded data is stored in json format along with the base-64 encoded [iv](http://en.wikipedia.org/wiki/Initialisation_vector), a truncated, encrypted hash of the encryption password ('masterkey') and a string identifying the cypher:

    {
        "data": "snXFsnWoX2nm/NrE+zlYOrxUAVtw7tMDEqM8PWdGMhSgMA7wFO7zojaqiCdwT7EWJ0o5hVEdaOX7Wi1LGh7E3A==", 
        "cypher": "AES_CBC_256_16", 
        "iv": "f3diAvfPB2o40W/8//sIDw==", 
        "masterkey": "WOunnSzByYJR/ls0uwg9AQJcI+zSpEUMLvTxYNzk64U=", 
        "label": "example.com"
    }


# NOTES

I am by no means a security expert. The salted AES encryption used in keyfor is intended to be compatible with [CommonCrypto][] (and [RNCryptor][]) for ease of implementation on OS X, iOS and other platforms as explained by Rob Napier: [Properly encrypting with AES with CommonCrypto](http://robnapier.net/blog/aes-commoncrypto-564).

keyfor is similar to and influenced by [kip][], a password manager which uses [GnuPG][] for encryption. 

[kip]: https://github.com/grahamking/kip
[GnuPG]: http://www.gnupg.org/
[CommonCrypto]: http://opensource.apple.com/source/CommonCrypto/
[RNCryptor]: https://github.com/rnapier/RNCryptor