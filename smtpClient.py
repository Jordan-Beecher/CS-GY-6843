#CS-GY 6843 - Computer Networking
#Name - Jordan Beecher
#UNI - jab10032
#NYU Email - jab10032@nyu.edu 


from socket import *


def smtp_client(port=1025, mailserver='127.0.0.1'):
    msg_body = "My message"
    endmsg = "\r\n.\r\n"

    # Create socket called clientSocket and establish a TCP connection with mailserver and port
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((mailserver, port))
    recv = clientSocket.recv(1024).decode()
    #print(recv)
 
    # HELO
    heloCommand = 'HELO Alice\r\n'
    clientSocket.send(heloCommand.encode())
    recv1 = clientSocket.recv(1024).decode()
    #print(recv1)
    

    # MAIL FROM
    mailFrom = "MAIL FROM:<jab10032@nyu.edu>\r\n"
    clientSocket.send(mailFrom.encode())
    recv2 = clientSocket.recv(1024).decode()
    #print(recv2)
    

    # RCPT TO
    rcptTo = "RCPT TO:<misterjbeecher@gmail.com>\r\n"
    clientSocket.send(rcptTo.encode())
    recv3 = clientSocket.recv(1024).decode()
    #print(recv3)
  

    # DATA
    dataCommand = "DATA\r\n"
    clientSocket.send(dataCommand.encode())
    recv4 = clientSocket.recv(1024).decode()
    #print(recv4)
    

    # Send message headers and body
    message = f"From: jab10032@nyu.edu\r\nTo: misterjbeecher@gmail.com\r\nSubject: Test Mail\r\n\r\n{msg_body}\r\n"
    clientSocket.send(message.encode())

    # Message ends with a single period on a line
    clientSocket.send(endmsg.encode())
    recv5 = clientSocket.recv(1024).decode()


    # QUIT
    quitCommand = "QUIT\r\n"
    clientSocket.send(quitCommand.encode())
    recv6 = clientSocket.recv(1024).decode()
    #print(recv6)
    clientSocket.close()


if __name__ == '__main__':
    smtp_client(1025, '127.0.0.1')