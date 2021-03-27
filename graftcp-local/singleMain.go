package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/jedisct1/dlog"
)

func constructArgs(args []string) ([]string, []string){
	server := make([]string, 0, len(args))
	client := make([]string, 0, len(args))

	isCommand := false
	for _, arg := range args{
		if isCommand{
			client = append(client, arg)
		}else{
			if strings.HasPrefix(arg, "--server"){
				server = append(server, strings.TrimPrefix(arg, "--server"))
			}else if strings.HasPrefix(arg, "--client"){
				client = append(client, strings.TrimPrefix(arg, "--client"))
			}else{
				isCommand = true
				client = append(client, arg)
			}
		}
	}

	return server, client
}

func main(){
	cmdName := filepath.Base(os.Args[0])

	if (cmdName == "graftcp-local"){
		local_main(os.Args)
	}else{
		// todo: we need special handle on args like '--help' which trigger os.Exit
		// todo: randomly set and detect port number if no one specified
		serverArgs, clientArgs := constructArgs(os.Args[1:])
		serverArgs = append(os.Args[:1], serverArgs...)
		clientArgs = append(os.Args[:1], clientArgs...)
		log.Infof("server args: %v", serverArgs) // todo: we need to suppress or redirect logging
		log.Infof("client args: %v", clientArgs)

		go local_main(serverArgs)
		// todo: we may use a channle to notify the graftcp-local is ready to accept request
		time.Sleep(1 * time.Second) 

		os.Exit(client_main(clientArgs))
	}
}