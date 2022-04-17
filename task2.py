import socket
import time

operation = ""
result = 0
number = 0
next_port = 1337
IP = "10.10.155.74"

#end the program once the loop is complete
while next_port != 9765:
	#try until port 1337 is open, ignore ConnectionRefusedError
	try:
		# create an INET, STREAMing socket
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# attempting to connect to the web server on port 1337
		s.connect((IP, int(next_port)))
		#show if connection attempt was successful
		print("Connected!")
		# send some data to receive data
		request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % IP
		s.send(request.encode()) 
		# get some data. call the function twice here because once only returns the header.
		response = s.recv(1024)
		response = s.recv(1024)
		#format the response
		response = response.decode().split("\r\n\r\n")[1].split(" ")
		#print response for visibility
		print(response)
		#define variables
		operation = response[0]
		number = float(response[1])
		next_port = response[2]
		#
		if operation == "add":
			result += number
		elif operation == "minus":
			result -= number
		elif operation == "multiply":
			result *= number
		elif operation == "divide":
			result /= number
		else:
			continue

		s.close()
		#print temporary result for visibility
		print(result)
		#wait until new port is available
		time.sleep(3.5)

	#exception: if port is closed, then try again
	except ConnectionRefusedError:
		#print("port closed")
		#new try every 0.2 seconds
		time.sleep(0.2)
	#sometimes there is a timeout error. then we wait until the current port is open again. Internet connection stable?
	except TimeoutError:
		time.sleep(0.2)

print("You have reached the end! Here is your flag: "+ int(round(result, 2)))