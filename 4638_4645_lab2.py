# Don't forget to change this file's name before submission.
import sys
import os
import enum
import socket

class HttpRequestInfo(object):

    def __init__(self, client_info, method: str, requested_host: str,
                 requested_port: int,
                 requested_path: str,
                 headers: list):
        self.method = method
        self.client_address_info = client_info
        self.requested_host = requested_host
        self.requested_port = requested_port
        self.requested_path = requested_path
        # Headers will be represented as a list of lists
        # for example ["Host", "www.google.com"]
        # if you get a header as:
        # "Host: www.google.com:80"
        # convert it to ["Host", "www.google.com"] note that the
        # port is removed (because it goes into the request_port variable)
        self.headers = headers

    def to_http_string(self):
        message=""
        request_line=self.method+" "+self.requested_path+" HTTP/1.0\r\n"
        headers=""
        for header in self.headers:
            headers=headers+header[0]+": "+header[1]+"\r\n"

        message= message+request_line+headers+"\r\n"
        return message

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def construct_message(self):

        return self.to_byte_array(self.to_http_string())

    def display(self):
        print(f"Client:", self.client_address_info)
        print(f"Method:", self.method)
        print(f"Host:", self.requested_host)
        print(f"Port:", self.requested_port)
        stringified = [": ".join([k, v]) for (k, v) in self.headers]
        print("Headers:\n", "\n".join(stringified))


class HttpErrorResponse(object):
    """
    Represents a proxy-error-response.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message

    def to_http_string(self):
        error_message = self.code+" "+self.message
        return error_message

    def to_byte_array(self, http_string):
        """
        Converts an HTTP string to a byte array.
        """
        return bytes(http_string, "UTF-8")

    def construct_message(self):
        self.display()
        return self.to_byte_array(self.to_http_string())

    def display(self):
        print(self.to_http_string())


class HttpRequestState(enum.Enum):
    """
    The values here have nothing to do with
    response values i.e. 400, 502, ..etc.
    Leave this as is, feel free to add yours.
    """
 
    INVALID_INPUT = 0
    NOT_SUPPORTED = 1
    GOOD = 2
    PLACEHOLDER = -1


def entry_point(proxy_port_number):
    setup_sockets(proxy_port_number)
    print("*" * 50)
    print("[entry_point] Implement me!")
    print("*" * 50)
    return None

def receive_data(conn):
    buffer = ''
    last_received = ''

    while 1:
        data = conn.recv(1024)
        data = data.decode('UTF-8')
        buffer += data
        if data == "\r\n" and last_received == "\r\n": break
        last_received = data
        if not data: break
        print("received data:", data)
        # conn.send(data)
    return buffer



def print_cache(client_cache):
    for key, value in client_cache.items() :
        print ("key",key,"value",value)

def setup_sockets(proxy_port_number):
    print("Starting HTTP proxy on port:", proxy_port_number)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", int(proxy_port_number)))
    s.listen(20)
    # conn, client_addr = s.accept()
    do_socket_logic(s,proxy_port_number)
   
    return None


def do_socket_logic(s,proxy_port_number):
    client_cache = {}

    while 1:
        conn, client_addr = s.accept()
        buffer=receive_data(conn)
        response_msg = http_request_pipeline(('127.0.0.1', proxy_port_number), buffer) 
        isError = isinstance(response_msg, HttpErrorResponse)
        if isError==True:
            error_message = response_msg.construct_message()
            conn.sendall(error_message)
        else:
            send_data_to_client(client_cache,response_msg,conn)
        conn.close()



def send_data_to_client(client_cache,response_msg,conn):
    url=response_msg.requested_host+response_msg.requested_path
    if url in client_cache:
        print("I FOUND DATA IN CACHE, NO NEED TO CONNECT THE SERVER")
        conn.sendall(client_cache[url])   
    else:
        correct_message = response_msg.construct_message()
        s_from_proxy_to_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_from_proxy_to_server.connect((response_msg.requested_host, response_msg.requested_port))
        s_from_proxy_to_server.send(correct_message)
        # conn.sendto(correct_message,(response_msg.requested_host, response_msg.requested_port))
        data=receive_html(s_from_proxy_to_server)
        client_cache[response_msg.requested_host+response_msg.requested_path]=data
        print("data _ decoded",data.decode('UTF-8'))
        conn.sendall(data)

def receive_html(s_from_proxy_to_server):
    data=b''
    while True:
        data_from_server_to_proxy = s_from_proxy_to_server.recv(8192)
        if len(data_from_server_to_proxy)<=0:
            break 
        data+=data_from_server_to_proxy
    print("LENGTH OF DATA",len(data))
    return data


def http_request_pipeline(source_addr, http_raw_data):

    # Parse HTTP request
    validity = check_http_request_validity(http_raw_data)

    if validity.value==2:
        return parse_http_request(source_addr,http_raw_data)
    else:
        if validity.value==0:
            code='400'
            message='Bad Request'
        else:
            code='501'
            message='Not Implemented'
        return HttpErrorResponse(code,message)

    print("*" * 50)
    print("[http_request_pipeline] Implement me!")
    print("*" * 50)
    return None


def parse_http_request(source_addr, http_raw_data):
    # client_info, method: str, requested_host: str,
    #              requested_port: int,
    #              requested_path: str,
    #              headers: list

    data_lines = http_raw_data.split("\r\n")
    first_line = data_lines[0].split()
    method = first_line[0]
    url=first_line[1]
    headers=[]

    if url[0]=='/':
        requested_path = url
    else:
        requested_host,requested_path = parse_url(url)
        port,requested_host=check_port(requested_host)


    for i in range(1,len(data_lines)-2):
        if data_lines[i]=='':
            continue

        splitted_line = data_lines[i].split(': ')
        if splitted_line[0]=='Host':
            #call someething here to check port number and extract it from address
            requested_host=splitted_line[1]
            port,requested_host =check_port(requested_host)           
            headers.append([splitted_line[0],requested_host])
        else:   
            headers.append([splitted_line[0],splitted_line[1]])
    


    request_obj = HttpRequestInfo(source_addr,method, requested_host, port, requested_path,headers)
    sanitize_http_request(request_obj)
    print("REQUEST",request_obj.headers)
    return request_obj

def parse_url(url):
    # if ':' in url:
    index=1

    if 'http' in url:
        splitted = url.split("/",3)
        # host=splitted[0]+"//"+splitted[2]
        host=splitted[2]
        index=3
    else:
        splitted = url.split("/",1)
        host=splitted[0]

    print("splitted",splitted,len(splitted))
    if len(splitted)==index:
        requested_path = "/"
    else:
        requested_path = "/"+splitted[index]
    
    return host,requested_path

def check_port(url):
    port=80
    print("HIIII,",url)
    port_split=url.split(':')
    print("len of split",len(port_split))
    if len(port_split)==3: #check if http://blahblah:800
        port=int(port_split[2])
        url=port_split[0]+':'+port_split[1]
    elif len(port_split)==2:
        print("split_port",port_split)
        port=int(port_split[1])
        url=port_split[0]
        

    return port,url

    
def check_http_request_validity(http_raw_data) -> HttpRequestState:
    methods=['HEAD', 'POST', 'PUT','DELETE','CONNECT','OPTIONS','TRACE','PATCH']
    data_lines = http_raw_data.split("\r\n")
    first_line = data_lines[0].split()
    http_version='HTTP/1.0'
    if len(first_line)!= 3 and http_version not in first_line:
        return HttpRequestState.INVALID_INPUT

    method=first_line[0]
    print("method",method)
    url=first_line[1]
   
    # 0 for absolute and 1 for relative 
    url_type = 0

    
    if url[0]=='/':
        url_type=1

    
    if url_type==1 and 'Host: ' not in data_lines[1]:
        return HttpRequestState.INVALID_INPUT

    for i in range(1,len(data_lines)-2):
        if data_lines[i]=='':
            continue

        if ': ' not in data_lines[i]:
            return HttpRequestState.INVALID_INPUT
    
 

    if method in methods :
        return HttpRequestState.NOT_SUPPORTED
    elif method!='GET':
        return HttpRequestState.INVALID_INPUT
 
    return HttpRequestState.GOOD


def sanitize_http_request(request_info: HttpRequestInfo):
    headers=request_info.headers
    host=request_info.requested_host

    if len(headers) ==0 or headers[0][0]!="Host":
        headers.insert(0,['Host',host])

    request_info.headers=headers


def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comand-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def check_file_name():
    """
    Checks if this file has a valid name for *submission*
    leave this function and as and don't use it. it's just
    to notify you if you're submitting a file with a correct
    name.
    """
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_){,2}lab2\.py", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    else:
        print(f"[LOG] File name is correct.")


def main():
    """
    Please leave the code in this function as is.
    To add code that uses sockets, feel free to add functions
    above main and outside the classes.
    """
    print("\n\n")
    print("*" * 50)
    print(f"[LOG] Printing command line arguments [{', '.join(sys.argv)}]")
    check_file_name()
    print("*" * 50)

    # This argument is optional, defaults to 18888
    proxy_port_number = get_arg(1, 18888)
    entry_point(proxy_port_number)


if __name__ == "__main__":
    main()