
import socket
import random
from Crypto.Cipher import AES


# Removes PKCS#7 padding 
# Note: same as:  unpad = lambda padded : padded[0:-ord(padded[-1])]
def unpad(padded : bytes) -> bytes:
	size= len(padded)
	padlen= padded[size-1]
	return padded[:size-padlen]


#
# NS-Lab-07, Exercise 3.
#
if __name__=="__main__":
	server= "netsec.unipr.it"
	port= 9001
	
	p= 171718397966129586011229151993178480901904202533705695869569760169920539808075437788747086722975900425740754301098468647941395164593810074170462799608062493021989285837416815548721035874378548121236050948528229416139585571568998066586304075565145536350296006867635076744949977849997684222020336013226588207303
	g= 2
	print("p:",p)
	print("g:",g)

	# choose a private value xc and compute yc
	xc= random.getrandbits(512)
	print("xc:",xc)
	yc= pow(g,xc,p)
	print("yc:",yc)
	
	# send client private value xc
	print("connecting to",server,port)
	s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server,port))
	io= s.makefile("rw")
	io.write(str(yc))
	io.write("\r\n")
	io.flush()
	
	# receive server public value ys
	ys= int(io.readline())
	print("ys:",yc)
	
	# compute DH secret
	dh= pow(ys,xc,p)
	print("dh:",dh)
	dh= dh.to_bytes(128,'big')
	print("dh:",dh.hex())
	
	# receive ciphertext
	hexdata= io.readline()
	ciphertext= bytearray.fromhex(hexdata)
	print("ciphertext:",ciphertext.hex())
	s.close()
	
	# decrypt ciphertext
	key= dh[:16] # first 16 byes of the DH secret
	print("key:",key.hex())
	iv= bytes([0x0]) * 16 # iv=0
	print("iv:",iv.hex())
	cipher= AES.new(key,AES.MODE_CBC,iv)
	plaintext= cipher.decrypt(ciphertext)
	print("padded plaintext:",plaintext.hex())
	
	# remove padding
	plaintext= unpad(plaintext)
	print("unpad plaintext:",plaintext.hex())
	print("message:",plaintext.decode())

