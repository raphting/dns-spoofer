DNS Proxy-like application
==========================
This tool helps you to analyze DNS packets. It will capture a DNS-request and send it to your preferred DNS-server. The reply is also captured, can be tampered, and forwarded back to the client.
This tool was written from scratch to learn about the DNS protocol and hence does not use any external DNS library.

Usage
-----
Just start the tool with `go run intercept.go`, to listen on UDP port :2323. With the `-p` flag you can change the port.

TODO
----
There is some more work to do to use this tool in production or whatever official use you might think of. Most important would be to separate requests not only by the DNS-id but also by user IP. Second is the recursive parsing of names which has to be coded. It is not trivial since you could craft a never ending recursion as a DoS attack if not thoughtfully implemented.
