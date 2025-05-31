# Pyenv
export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

# spaceship promt set up
source /opt/homebrew/opt/spaceship/spaceship.zsh

# autocompletions
source <(kubectl completion zsh)
source <(podman completion zsh)

# zsh settings
autoload -Uz compinit
zstyle ':completion:*' menu select
fpath+=~/.zfunc
compinit

# iterm2 terminal integration
test -e "${HOME}/.iterm2_shell_integration.zsh" && source "${HOME}/.iterm2_shell_integration.zsh"

# aliases 
alias k='kubectl'
alias d='docker'
alias dc='docker compose'
alias tf='terraform'
alias gs='git status'
