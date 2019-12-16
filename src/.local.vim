let g:ale_linters= { 'c' : ['g++'], 'cpp' : ['g++'] }
let g:ale_c_gcc_options="-I. -I./lib/kernel -I./lib -Wall"
let g:ale_cpp_gcc_options="-I. -I./lib/kernel -I./lib -Wall"
function! LoadCscope()
  let db = findfile("cscope.out", ".;")
  if (!empty(db))
    let path = strpart(db, 0, match(db, "/cscope.out$"))
    set nocscopeverbose " suppress 'duplicate connection' error
    exe "cs add " . db . " " . path
    set cscopeverbose
  " else add the database pointed to by environment variable 
  elseif $CSCOPE_DB != "" 
    cs add $CSCOPE_DB
  endif
endfunction
au BufEnter /* call LoadCscope()
