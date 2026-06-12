#CS-GY 6843 - Computer Networking
#Name - Jordan Beecher
#UNI - jab10032
#NYU Email - jab10032@nyu.edu 

from socket import *
import sys

def webServer(port=13331):
  serverSocket = socket(AF_INET, SOCK_STREAM)
  serverSocket.bind(("", port))
  serverSocket.listen()
  
  while True:
    
    print('Ready to serve...')
    connectionSocket, addr = serverSocket.accept()
    
    try:
      message = connectionSocket.recv(1024)
      filename = message.split()[1]
      f = open(filename[1:], 'rb')
      
      
      outputdata = b"HTTP/1.1 200 OK\r\n"
      outputdata += b"Server: MyWebServer/1.0\r\n"
      outputdata += b"Connection: close\r\n"
      outputdata += b"Content-Type: text/html; charset=UTF-8\r\n"
      outputdata += b"\r\n"

               
      for i in f: 
        outputdata += i
        connectionSocket.sendall(outputdata)
      
      connectionSocket.close() 
      
    except Exception as e:
      outputdata = b"HTTP/1.1 404 Not Found\r\n"
      outputdata += b"Server: MyWebServer/1.0\r\n"
      outputdata += b"Connection: close\r\n"
      outputdata += b"Content-Type: text/html; charset=UTF-8\r\n"
      outputdata += b"\r\n"
      connectionSocket.sendall(outputdata)
      connectionSocket.close()
      

  # Commenting out the below (some use it for local testing). It is not required for Gradescope, and some students have moved it erroneously in the While loop. 
  # DO NOT PLACE ANYWHERE ELSE AND DO NOT UNCOMMENT WHEN SUBMITTING, YOU ARE GONNA HAVE A BAD TIME
  #serverSocket.close()
  #sys.exit()  # Terminate the program after sending the corresponding data

if __name__ == "__main__":
  webServer(13331)