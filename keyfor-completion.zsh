#!/zsh
# 
# Zsh completion for keyfor
# 
# INSTALLATION
# 
# First install keyfor from 
# https://github.com/randomsequence/keyfor
# 
# Make sure autocompletion is enabled in your shell, typically
# by adding this to your .zshrc:
# 
#     autoload -U compinit && compinit
# 
# Then copy this file somewhere (e.g. ~/.keyfor-completion.zsh) and put the
# following in your .zshrc:
# 
#     source ~/.keyfor-completion.zsh
# 
# CREDITS
# 
# Written by Johnnie Walker

_keyfor()
{
    key_path="$HOME/Dropbox/apps/Key For"
    if [ -e "$key_path" ]; then
        compadd -M 'm:{[:lower:]}={[:upper:]}' $( find "$key_path" -type f -exec basename \{\} \; )
    fi
}
compdef _keyfor keyfor
