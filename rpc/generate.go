package sdk

//go:generate protoc -Iproto --go_out=. types.proto

//go:generate protoc -Iproto --go-grpc_out=. --go_out=. --go_opt=Mtypes.proto=go.alargerobot.dev/gatekeeper/sdk/rpc/types --go-grpc_opt=Mtypes.proto=go.alargerobot.dev/gatekeeper/sdk/rpc/types EndpointManager.proto
//go:generate protoc -Iproto --go-grpc_out=. --go_out=. --go_opt=Mtypes.proto=go.alargerobot.dev/gatekeeper/sdk/rpc/types --go-grpc_opt=Mtypes.proto=go.alargerobot.dev/gatekeeper/sdk/rpc/types ConfigService.proto
