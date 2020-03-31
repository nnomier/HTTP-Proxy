# HTTP-PROXY

**Ordinarily, HTTP is a client-server protocol. The client (usually your web browser) communicates directly with the server (the web server software). However, in some circumstances it may be useful to introduce an intermediate entity called a proxy. Conceptually, the proxy sits between the client and the server. In the simplest case, instead of sending requests directly to the server the client sends all its requests to the proxy. The proxy then opens a connection to the server, and passes on the client's request. The proxy receives the reply from the server, and then sends that reply back to the client. Notice that the proxy is essentially acting like both a HTTP client (to the remote server) and a HTTP server (to the initial client).**

You can learn more about it from the RFC [here](https://www.w3.org/Protocols/rfc1945/rfc1945)

## Project Steps:
1. Establishing a socket connection that it can use to listen for incoming connections.
2. Parsing The request from the client and making sure it's valid
3. Getting Data from the Remote Server
4. Returning Data to the Client
5. Supporting multiple clients using threads
