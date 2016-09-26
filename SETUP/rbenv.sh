# rbenv setup
export RBENV_ROOT=/usr/local/rbenv
export PATH="$RBENV_ROOT/bin:$PATH"
export PATH="$HOME/.rbenv/shims:$HOME/.rbenv/bin:$PATH"
export GEM_HOME="$HOME/.gem"
export GEM_PATH="$HOME/.gem"
export PATH="$HOME/.gem/bin:$PATH"
eval "$(rbenv init -)"
