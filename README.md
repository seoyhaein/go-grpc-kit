# go-grpc-kit

## buf 에서 사용한 버전과 맞춰야 한다. (중요)
- google.golang.org/protobuf@v1.36.6
- google.golang.org/grpc@v1.64.1
- go mod 에서 google.golang.org/grpc v1.64.1 google.golang.org/protobuf v1.36.6 // indirect 만 수정해주고   
- 나머지 대표적으로 google.golang.org/genproto/googleapis/rpc v0.0.0-20250218202821-56aae31c358a // indirect  
- 같은 녀석들은 go mod tidy 로 해결 하면 될듯 하다. buf 에서는 일단 최신 googleapis 사용하도록 했으므로   

## todo
- server.go 에서 아래 코드를 주석 처리 했는데 service 에 대한 종속성이 발생했는데 이걸 해결 하도록 메서드를 수정할 필요가 있다.  
- Server() 수정해야함.  

```aiignore
    // service.RegisterDataBlockServiceServer(grpcServer)
    // service.RegisterDBApisServiceServer(grpcServer)
```
