package main

import (
	"os"
	"path/filepath"
)

func main(){
	cmdName := filepath.Base(os.Args[0])

	if (cmdName == "graftcp-local"){
		local_main(os.Args)
	}else{
		client_main(os.Args)
	}
}