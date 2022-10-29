
import socket
import random
import hashlib


# Removes PKCS#7 padding 
# Note: same as:  unpad = lambda padded : padded[0:-ord(padded[-1])]
def unpad(padded : bytes) -> bytes:
	size= len(padded)
	padlen= padded[size-1]
	return padded[:size-padlen]

if __name__=="__main__":
	server= "netsec.unipr.it"
	port= 7022
	
	p_DH = 171718397966129586011229151993178480901904202533705695869569760169920539808075437788747086722975900425740754301098468647941395164593810074170462799608062493021989285837416815548721035874378548121236050948528229416139585571568998066586304075565145536350296006867635076744949977849997684222020336013226588207303
	g_DH = 2

	# choose a private key for DH and compute yClient = (g_DH ^ (xClient)) mod p_DH
	xClient= random.getrandbits(512)
	yClient= pow(g_DH,xClient,p_DH)
	
	# send client private value yClient
	s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server,port))

	io= s.makefile("rw")
	io.write('HELLO ' + str(yClient))
	io.write("\r\n")
	io.flush()
	
	# receive server public value yb
	helloServerMessage = io.readline()

	if(helloServerMessage[:6] != 'HELLO '):
		print('Response Not Valid')
		s.close()
		exit()		

	dh= pow(int(helloServerMessage[6:]), xClient, p_DH)
	dh= dh.to_bytes(128,'big')

	serverCertificateMessage = io.readline()
	if(serverCertificateMessage[:12] != 'CERTIFICATE '):
		print(serverCertificateMessage[:12])
		print('Response Not Valid')
		s.close()
		exit()	
	serverCertificateVerifyMessage= io.readline()
	if(serverCertificateVerifyMessage[:19] != 'CERTIFICATE_VERIFY '):
		print('Response Not Valid')
		s.close()
		exit()	
	serverFinishedMessage= io.readline()
	if(serverFinishedMessage[:9] != 'FINISHED '):
		print('Response Not Valid')
		s.close()
		exit()	

	mac_s = bytes.fromhex(serverFinishedMessage[9:])
	#print('mac_s ' , mac_s)
	#print('secret' , dh[112:128])
	mac_c =  dh[112:128] + mac_s
	#print('tot ', mac_c)
	result = hashlib.sha256(mac_c)


	io.write('FINISHED ' + result.hexdigest())
	io.write("\r\n")
	io.flush()
	dataMessage = io.readline()

	print('response ', dataMessage)

	s.close()

	exit()

