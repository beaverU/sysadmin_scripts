:syntax on
set number             " Show line numbers
"set relativenumber     " Show relative line numbers
set cursorline         " Highlight the current line
set showcmd            " Show incomplete commands in the status line
set wildmenu           " Enhanced command-line completion
set ruler              " Show cursor position
set hlsearch           " Highlight search results
set incsearch          " Incremental search (search as you type)
set ignorecase         " Case-insensitive search
set smartcase          " Case-sensitive search if query contains uppercase

set tabstop=4          " Set tab width to 4 spaces
set shiftwidth=4       " Auto-indent by 4 spaces
set expandtab          " Convert tabs to spaces
set autoindent         " Maintain indent from previous line
set smartindent        " Automatically indent new lines

set background=dark    " Optimize colors for dark backgrounds
set termguicolors      " Enable 24-bit color support
"colorscheme desert     " Set a colorscheme (change as needed)

set mouse=a

set lazyredraw         " Redraw screen only when needed (improves performance)
set updatetime=300     " Reduce time for CursorHold events

autocmd Filetype gitcommit setlocal spell textwidth=72
