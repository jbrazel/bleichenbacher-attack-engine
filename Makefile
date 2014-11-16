SRC=	ssltest.o union.o client.o bleichenbacher.o
TARGETS=	bruteforce
LDFLAGS=	-lcrypto

all:	$(TARGETS)

$(TARGETS):	$(SRC)
		$(CC) -o $@ $(SRC) $(LDFLAGS)

clean:  
	-rm $(SRC) $(TARGETS)



