#Keyfor

keyfor - keeps usernames & passwords. Create, Retrieve, Edit Strong Passwords with AES Encryption

Keyfor stores each username & password combination ('key') in a separate encrypted file which can be synced using Dropbox. A master password, stored in your system keyring, is used to encrypt and decrypt your keys.

##Synposis

    keyfor [add | edit | delete | verify | refresh] [--username=USER] [--print] (<label> | <label> <subset>)
    keyfor all [verify | refresh | list]
    keyfor (-h | --help)
    keyfor --version

##Install

Latest development version:

 1. Clone the repo: `git clone https://github.com/randomsequence/keyfor.git`
 2. Install: `sudo python setup.py install`

##Commands

### get

    keyfor example.com

What it does:

1. Search your keys directory for a file named `example.com`
2. Search your system keychain for an application password named 'keyfor'. Use your keychain password to decrypt the password
3. Prints your username in bold, and any notes you stored.
4. Copies your password to the clipboard

    keyfor example.com 1,2,5

As above, but only the first, second and fifth characters of the password are copied to the clipboard

### add

    keyfor add example.com
    
What it does:    
    
1. Asks you for a username & password, optionally generating a random password
2. Search your system keychain for an application password named 'keyfor'. Use your keychain password to encrypt the username & password
3. Writes the encrypted username and password to text file `example.com`
4. Copies the new password to the clipboard

### edit

    keyfor edit example.com

Edit the username & password for the specified key

### delete

    keyfor delete example.com
    
Deletes the data for the specified label 

### verify

    keyfor verify example.com

Verifies that the credentials stored for example.com were encrypted with your keyring password

### refresh

    keyfor refresh example.com

Decrypts the named key, then re-encrypts using the current encryption scheme.

## Configuration

Configuration is read from the file `~/.keyfor`. The default configuration is:

    [DEFAULT]
    key_path = ~/Dropbox/apps/Key For   # Where your key files are stored
    password_length = 12                # Length for randomly generated passwords

## Label tab completion in zsh

Make sure autocompletion is enabled in your shell, typically by adding this to your .zshrc:

    autoload -U compinit && compinit

Modify key_path in `zshrc-completion.zsh` to match your configuration. Copy `keyfor-completion.zsh` somewhere (e.g. ~/.keyfor-completion.zsh)
and put the following in your .zshrc:

    source ~/.zshrc-completion.zsh

## Encryption

The default encryption scheme in keyfor is AES 256, CBC mode, padded with [PKCS#7][]. 

The encrypted data is a UTF8-encoded [JSON][] dump of a map containing the username, password:

    {
      "username": "mrwalker",
      "password": "secret101"
    }

Any other information in this map will be preserved in future writes.
    
[PKCS#7]: http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
[JSON]: http://json.org

##File Format

The encrypted, base-64 encoded data is stored as UTF8-encoded JSON, along with the base-64 encoded [iv](http://en.wikipedia.org/wiki/Initialisation_vector), a truncated, encrypted hash of the encryption password ('masterkey') and a string identifying the cypher:

    {
        "data": "snXFsnWoX2nm/NrE+zlYOrxUAVtw7tMDEqM8PWdGMhSgMA7wFO7zojaqiCdwT7EWJ0o5hVEdaOX7Wi1LGh7E3A==", 
        "cypher": "AES_CBC_256_16", 
        "iv": "f3diAvfPB2o40W/8//sIDw==", 
        "masterkey": "WOunnSzByYJR/ls0uwg9AQJcI+zSpEUMLvTxYNzk64U=", 
        "label": "example.com"
    }

## Dependencies

* [keyring](https://bitbucket.org/kang/python-keyring-lib)
* [pycrypto](https://www.dlitz.net/software/pycrypto/)
* [docopt](https://github.com/docopt/docopt)

## Notes

I am by no means a security expert. The salted AES encryption used in keyfor is intended to be compatible with [CommonCrypto][] (and [RNCryptor][]) for ease of implementation on OS X, iOS and other platforms as explained by Rob Napier: [Properly encrypting with AES with CommonCrypto](http://robnapier.net/blog/aes-commoncrypto-564).

keyfor is similar to and influenced by [kip][], a password manager which uses [GnuPG][] for encryption. 

[kip]: https://github.com/grahamking/kip
[GnuPG]: http://www.gnupg.org/
[CommonCrypto]: http://opensource.apple.com/source/CommonCrypto/
[RNCryptor]: https://github.com/rnapier/RNCryptor