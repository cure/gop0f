# Gop0f - Client library for p0f passive fingerprinting

This is forked from https://github.com/gurre/gop0f (thanks!). I updated the code so that the cli tool is just functional enough to work for querying p0f3.

## Installing
```
go get github.com/cure/gop0f
```

## Using

Using the library in your service:
```
import (
  "github.com/cure/gop0f"
  "net"
)

p0fclient, err := gop0f.New("/var/run/p0f.socket")
if err != nil {
  panic(err)
}
resp, err := p0fclient.Query(net.ParseIP("127.0.0.1"))
if err != nil {
  panic(err)
}
```

Using the included cli tool:
```
$ ./p0f-cli -q 127.0.0.1)
Linux 2.2.x-3.x [generic]
```

## Further reading
Read more about [p0f](http://lcamtuf.coredump.cx/p0f3/) by Michal Zalewski
