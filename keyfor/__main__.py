"""keyfor - create, store & retrieve passwords with pluggable AES encryption

Usage:
  keyfor [add | edit | delete | verify | refresh] [-u <username>] [-s <subset>] <label>
  keyfor all [verify | refresh | list]
  keyfor (-h | --help)
  keyfor --version

Options:
  -u --username Keychain username
  -s --subset   Copy a subset of the password to the clipboard, for example: 1,2,5. Indexes begin at 1, not 0
  -h --help     Show this screen
  --version     Show version"""

import sys
import os
import keyring
import getpass
import subprocess
from docopt import docopt
from key import KeyChain, MasterKey, Key
import ConfigParser
from keyfor import VERSION

def read_config():
    GENERAL = 'General'
    path = os.path.expanduser('~/.keyfor')
    defaults = {
        'key_path': '~/Dropbox/apps/Key For', 
        'password_length': 12
        }
    config = ConfigParser.RawConfigParser(defaults)
    config.read(path)
    if not config.has_section(GENERAL):
        config.add_section(GENERAL)
    return {
            'key_path': config.get(GENERAL, 'key_path'),
            'password_length': config.getint(GENERAL, 'password_length'),                
            }

config = read_config()

# print repr(config)

def get_credentials(username=None, password=None):
    """Asks the user to input a username & password, using previous values or appropriately derived defaults"""
    if username is None:
        username = getpass.getuser()
    input_username = raw_input('username ('+username+')')
    if len(input_username) > 0:
        username = input_username
    if password is None:
        input_password = getpass.getpass('password (random)')
        if len(input_password) == 0:
            password = Key.generate_password(config['password_length'])
        else:
            password = input_password
    else:
        input_password = raw_input('password (previous)')
        if len(input_password) > 0:
            password = input_password
    return {'username': username, 'password': password}

def check_credentials(username=None):
    """Checks for a keyring password for the specified user. Prompts the user to create a keyring password if not found"""
    if username is None:
        username = getpass.getuser()
    password = keyring.get_password('keyfor', username)
    if password is None:
        print """Create a master password. All passwords stored with keyfor are encrypted using a master password, stored in your system keyring"""
        credentials = get_credentials(username=username)
        keyring.set_password('keyfor', credentials['username'], credentials['password'])
    return {'username': username, 'password': password}

def get_masterkey(username=None):
    """Returns a master key for the specified username. Prompts the user to create a master key if not found"""
    credentials = check_credentials(username)
    return MasterKey(username=credentials['username'], password=credentials['password'])

def copy_to_clipboard(msg):
    """Copy given message to clipboard"""
    
    if sys.platform == 'darwin':
        CLIPBOARD_CMD = 'pbcopy'
    else:
        CLIPBOARD_CMD = 'xclip'

    try:
        proc = subprocess.Popen(CLIPBOARD_CMD.split(), stdin=subprocess.PIPE)
        proc.stdin.write(msg.encode("utf8"))
        proc.communicate()
    except OSError as err:
        print('{} -- {}'.format(CLIPBOARD_CMD, err))
        print('{} is probably not installed'.format(CLIPBOARD_CMD))
        
def show_key(key, subset):
    print "username for " + key.label + ": " + key.username +", ",
    password = key.password
    if subset:
        indexes = subset.split(",")
        password = ''
        for index in indexes:
            print "subset index "+str(int(index)-1)
            password += key.password[int(index)-1]
    copy_to_clipboard(password)
    print "password copied to clipboard"    

def key_exists(keychain, label):
    keys = keychain.list_keys()
    exists = label in keys
    if not exists:
        print "No key stored for label: " + label
    return exists

def read_key(keychain, label):
    key = None
    if key_exists(keychain, label):
        key = keychain.read_key(label)
        if key is None:
            print "Failed do decrypt key for label: " + label
    return key

def verify_key(keychain, label):
    verified = keychain.verify_key(label)
    if verified:
        print "Key for label: "+label+" was encrypted with current master key"
    else:
        print "Key for label: "+label+" was not encrypted with current master key"
    return verified
    
def refresh_key(keychain, label):
    key = read_key(keychain, label)
    if key:
        keychain.save_key(key)
        print "refreshed key for: "+key.label

def main():    
    args = docopt(__doc__, version='keyfor '+VERSION)
    
    # print repr(args)

    masterkey = get_masterkey(username=args['--username'])
    keychain = KeyChain(path=os.path.expanduser(config['key_path']), masterkey=masterkey)
    
    if '<label>' in args and args['<label>']:
        label = args['<label>']
        subset = args['<subset>']
        
        print subset
        
        if 'add' in args and args['add']:
            keys = keychain.list_keys()
            if label in keys:
                print "Key already stored for label: " + label +", -u to update or ommit flags to read"
                return
            print "Create a new key for: " + label
            credentials = get_credentials(username=masterkey.username)
            key = Key(label=label, username=credentials['username'], password=credentials['password'])
            keychain.save_key(key)
            print "created new key for: "+key.label
            show_key(key, subset)
            
        elif 'edit' in args and args['edit']:
            key = read_key(keychain, label)
            if key:
                credentials = get_credentials(username=key.username, password=key.password)
                key.username = credentials['username']
                key.password = credentials['password']
                keychain.save_key(key)
                print "Updated key for label: " + label
                show_key(key, subset)
                
        elif 'delete' in args and args['delete']:
            if key_exists(keychain, label):
                keychain.delete_key(label)
                
        elif 'refresh' in args and args['refresh']:
            if key_exists(keychain, label):
                refresh_key(keychain, label)
                
        elif 'verify' in args and args['verify']:
            if key_exists(keychain, label):
                verify_key(keychain, label)
                    
        else:
            key = read_key(keychain, label)
            if key:
                show_key(key, subset)
                
    elif 'all' in args and args['all']:
                
        if 'refresh' in args and args['refresh']:
            for label in keychain.list_keys():
                refresh_key(keychain, label)
        
        elif 'verify' in args and args['verify']:
            for label in keychain.list_keys():
                verify_key(keychain, label)
        
        elif 'list' in args and args['list']:
            for label in keychain.list_keys():
                print label
        
    else:
        print __doc__

if __name__ == "__main__":
    main()