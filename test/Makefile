all: DTCPTest

DTCPTest: DTCPTest.cpp DTCPTest.h $(DTCP_ROOT)/DTCPAPI.h $(DTCP_ROOT)/DTCPError.h
	g++ -g -fPIC -fpermissive -I$(DTCP_ROOT) -o DTCPTest DTCPTest.cpp -ldl -lcurl -pthread
