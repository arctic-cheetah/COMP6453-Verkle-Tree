# This file must be used with "source bin/activate.csh" *from csh*.
# You cannot run it directly.
# Created by Davide Di Blasi <davidedb@gmail.com>.
# Ported to Python 3.3 venv by Andrew Svetlov <andrew.svetlov@gmail.com>

alias deactivate 'test $?_OLD_VIRTUAL_PATH != 0 && setenv PATH "$_OLD_VIRTUAL_PATH" && unset _OLD_VIRTUAL_PATH; rehash; test $?_OLD_VIRTUAL_PROMPT != 0 && set prompt="$_OLD_VIRTUAL_PROMPT" && unset _OLD_VIRTUAL_PROMPT; unsetenv VIRTUAL_ENV; unsetenv VIRTUAL_ENV_PROMPT; test "\!:*" != "nondestructive" && unalias deactivate'

# Unset irrelevant variables.
deactivate nondestructive

<<<<<<< HEAD:py3.10-env/bin/activate.csh
setenv VIRTUAL_ENV /home/lorikeet/COMP6453-Verkle-Tree/py3.10-env
=======
setenv VIRTUAL_ENV /home/shada/COMP6453/Term_Project/COMP6453-Verkle-Tree/.venv
>>>>>>> 018d44acc2253109027730bed878b80af6afbe4a:.venv/bin/activate.csh

set _OLD_VIRTUAL_PATH="$PATH"
setenv PATH "$VIRTUAL_ENV/"bin":$PATH"


set _OLD_VIRTUAL_PROMPT="$prompt"

if (! "$?VIRTUAL_ENV_DISABLE_PROMPT") then
    set prompt = '(py3.10-env) '"$prompt"
    setenv VIRTUAL_ENV_PROMPT '(py3.10-env) '
endif

alias pydoc python -m pydoc

rehash
