# MANI SHAH
# G00974705
# CS455 - PARTH PATHAK
# PA1 - DNS-CLIENT

import sys
import bitstring
from collections import OrderedDict
from socket import AF_INET,SOCK_DGRAM,socket,timeout

#Reads the command line
url = sys.argv[1].split(".")

#Header section of the response
responseHeader = OrderedDict()
#Question section of the response
responseQuestion = OrderedDict()
#List of RRs if there are multiple RRs
responseAnswers = []
#Single answer
responseAnswerSingle = OrderedDict()

#Header format of the DNS query
query = {
    "id": "0xefef",
    "qr":"0b0",
    "opcode":"0b0000",
    "aa":"0b0",
    "tc":"0b0",
    "rd":"0b1",
    "ra":"0b0",
    "z":"0b000",
    "rcode":"0b0000",
    "qdcount": 1,
    "ancount": 0,
    "nscount": 0,
    "arcount": 0
}
#Format of the data in the header of the DNS Query
queryFormat = ["hex=id",
               "bin=qr",
               "bin=opcode",
               "bin=aa",
               "bin=tc",
               "bin=rd",
               "bin=ra",
               "bin=z",
               "bin=rcode",
               "uint:16=qdcount",
               "uint:16=ancount",
               "uint:16=nscount",
               "uint:16=arcount"
               ]

# Prepares the dns query header section and the question section
def prepareMessage():
    print("Preparing DNS Query...")
    
    parseUrlForQuery()
    additionalEntry = "hex=qtype"
    queryFormat.append(additionalEntry)
    query["qtype"] = "0x0001"

    additionalEntry = "hex=qclass"
    queryFormat.append(additionalEntry)
    query["qclass"] = "0x0001"

    finalQueryFormat = ",".join(queryFormat)
    return finalQueryFormat

#Parses the url given in the command line argument
def parseUrlForQuery():
    qnameIndex = 0
    for word in url:
        additionalEntry = "hex=wordLen"+str(qnameIndex)
        queryFormat.append(additionalEntry)
        length = "0"+hex(len(word)).lstrip("0x")
        query["wordLen"+str(qnameIndex)] = "0x"+length
        qnameIndex+=1
        hexRep = ""
        for letter in word:
            currHexVal = hex(ord(letter)).lstrip("0x")
            hexRep += currHexVal
        additionalEntry = "hex=qnamePart"+str(qnameIndex)
        queryFormat.append(additionalEntry)
        query["qnamePart"+str(qnameIndex)] = "0x"+hexRep

    qnameIndex+=1
    additionalEntry = "hex=qnamePart"+str(qnameIndex)
    queryFormat.append(additionalEntry)
    query["qnamePart"+str(qnameIndex)] = "0x00"

#Sends the message to the google server and recieves the message
def sendMessage():
    attempts = 0
    preparedMessage = prepareMessage()
    finalQuery = bitstring.pack(preparedMessage,**query)
    serverName = "8.8.8.8"
    serverPort = 53
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    print("Sending DNS Query...")
    while attempts < 3:
        try:
            clientSocket.sendto(finalQuery.tobytes(), (serverName, serverPort))
            clientSocket.settimeout(5)
            break
        except timeout:
            attempts += 1
            print("No response, Attempt " + str(attempts)+ " of 3")
    if attempts == 3:
        print("No server response")
        exit(-1)
    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
    print("DNS Response received, Attempt ", attempts+1, " of 3")
    clientSocket.close()
    return modifiedMessage

# Processes the response received from the google server
def processResponse(dnsResponse):
    print("Processing DNS Response...")
    print("-------------------------------------")
    dnsResponse = bitstring.BitArray(bytes=dnsResponse)
    responseHex = dnsResponse.hex
    responseHeader["ID"] = "0x"+str(responseHex[0:4])
    parseFlags(responseHex[4:8])
    responseHeader["QDCOUNT"] = int(responseHex[8:12],16)
    responseHeader["ANCOUNT"] = int(responseHex[12:16],16)
    responseHeader["NSCOUNT"] = int(responseHex[16:20],16)
    responseHeader["ARCOUNT"] = int(responseHex[20:24],16)

    currIndex = parseResponseQuestion(responseHex)
    currEnd = 0

    numRR = responseHeader["ANCOUNT"]

    if numRR == 1: #If only one RR
        responseAnswerSingle["NAME"] = responseQuestion["QNAME"]
        currIndex += 4
        currEnd = currIndex+4
        responseAnswerSingle["TYPE"] = "0x"+str(responseHex[currIndex:currEnd])
        currIndex = currEnd
        currEnd = currIndex + 4
        responseAnswerSingle["CLASS"] = "0x" + str(responseHex[currIndex:currEnd])
        currIndex = currEnd
        currEnd = currIndex + 4
        ttl1 = int(responseHex[currIndex:currEnd],16)
        currIndex = currEnd
        currEnd = currIndex + 4
        ttl2 = int(responseHex[currIndex:currEnd],16)
        currIndex = currEnd
        currEnd = currIndex + 4
        responseAnswerSingle["TTL"] = ttl1 + ttl2
        responseAnswerSingle["RDLENGTH"] = int(responseHex[currIndex:currEnd],16)
        currIndex = currEnd
        currEnd = currIndex+2
        parseIP(responseHex,currIndex,currEnd)
    else: # More than one RR
        tempUrl = ""
        cname = ""
        alias = False
        if url[0] == "www":
            tempUrl = ".".join(url[1:])
        for i in range(responseHeader["ANCOUNT"]):
            currDict = OrderedDict()
            if alias:
                name = cname
            else:
                currEnd = currIndex + 4
                name = responseHex[currIndex:currEnd]
            if name == "c00c":
                name = responseQuestion["QNAME"]
            currDict["NAME"] = name
            currIndex = currEnd
            currEnd = currIndex + 4
            type = responseHex[currIndex:currEnd]
            currDict["TYPE"] = type
            currIndex = currEnd
            currEnd = currIndex + 4
            clas = responseHex[currIndex:currEnd]
            currDict["CLASS"] = clas
            currIndex = currEnd
            currEnd = currIndex + 8
            ttl = int(responseHex[currIndex:currEnd],16)
            currDict["TTL"] = ttl
            currIndex = currEnd
            currEnd = currIndex + 4
            rdlen = int(responseHex[currIndex:currEnd],16)
            currDict["RDLENGTH"] = rdlen
            if rdlen == 4:
                #parse url
                currIndex = currEnd
                currEnd = currIndex + 2
                ip = ""
                for i in range(rdlen):
                    ip += str(int(responseHex[currIndex:currEnd], 16))
                    currIndex = currEnd
                    currEnd = currIndex + 2
                    ip += "."
                ip = ip.rstrip(".")
                currDict["RDATA"] = ip
                currEnd += 2

            else:
                currIndex = currEnd
                currEnd = currIndex + 2

                if responseHex[currIndex:currEnd] == "c0":
                    cname = tempUrl
                    currDict["RDATA"] = cname
                    alias = True
                    currEnd = currIndex + 4
                    currIndex = currEnd
                    currEnd = currIndex + 4

                else:
                    index = currDict["RDLENGTH"]
                    i = 0
                    queryURL = ""
                    while i < index:
                        wordLen = int(responseHex[currIndex:currEnd],16)
                        currIndex = currEnd
                        currEnd = currIndex + 2
                        for i in range(wordLen):
                            queryURL += chr(int(responseHex[currIndex:currEnd], 16))
                            currIndex = currEnd
                            currEnd = currIndex + 2
                        queryURL += "."
                        tempIndex = currEnd + 2
                        if responseHex[currIndex:tempIndex] == "c010" or responseHex[currIndex:tempIndex] == "c0"\
                                or responseHex[currIndex:currEnd] == "c0":
                            queryURL += tempUrl
                            cname = queryURL
                            currDict["RDATA"] = cname
                            alias = True
                            currIndex = currEnd + 2
                            currEnd = currIndex + 4
                            break;
                        i += 1
            responseAnswers.append(currDict)

#Parses the question section of the response
def parseResponseQuestion(responseHex):
    queryURL = ""
    currIndex = 24
    currEnd = 26

    while responseHex[currIndex:currEnd] != "00":
        wordLen = int(responseHex[currIndex:currEnd],16)
        currIndex = currEnd
        currEnd = currIndex + 2
        for i in range(wordLen):
            queryURL += chr(int(responseHex[currIndex:currEnd], 16))
            currIndex = currEnd
            currEnd = currIndex + 2
        queryURL += "."
    responseQuestion["QNAME"] = queryURL.rstrip(".")
    currIndex = currEnd
    currEnd = currIndex + 4
    responseQuestion["QTYPE"] = "0x" + str(responseHex[currIndex:currEnd])
    currIndex = currEnd
    currEnd = currIndex + 4
    responseQuestion["QCLASS"] = "0x" + str(responseHex[currIndex:currEnd])

    return currEnd

#Parses the bits of the flag from the response
def parseFlags(flags):
    binFlagsVersion = bin(int(flags,16)).lstrip("0b")
    responseHeader["QR"] = binFlagsVersion[0:1]
    responseHeader["OPCODE"] = binFlagsVersion[1:5]
    responseHeader["AA"] = binFlagsVersion[5:6]
    responseHeader["TC"] = binFlagsVersion[6:7]
    responseHeader["RD"] = binFlagsVersion[7:8]
    responseHeader["RA"] = binFlagsVersion[8:9]
    responseHeader["Z"] =  int(binFlagsVersion[9:12],2)
    responseHeader["RCODE"] = int(binFlagsVersion[12:16],2)

#Parses the RDATA portion of the RR 
def parseIP(responseHex,currIndex,currEnd):
    ip = ""
    for i in range(responseAnswerSingle["RDLENGTH"]):
        ip += str(int(responseHex[currIndex:currEnd], 16))
        currIndex = currEnd
        currEnd = currIndex + 2
        ip += "."
    responseAnswerSingle["RDATA"] = ip.rstrip(".")

#Print the results from the response
def printResults():
    for key in responseHeader:
        print("Header."+str(key)+'='+str(responseHeader[key]))
    for key in responseQuestion:
        print("Question."+str(key)+ '='+ str(responseQuestion[key]))
    for key in responseAnswerSingle:
        print("Answer."+str(key)+ '='+ str(responseAnswerSingle[key]))
    for i in range(len(responseAnswers)):
        currDict = responseAnswers[i]
        for key in currDict:
            print("Answer"+str(i+1)+"." + str(key) + '=' + str(currDict[key]))
    print("-------------------------------------")

#Main
def main():
    dnsResponse = sendMessage()
    processResponse(dnsResponse)
    printResults()

if __name__ == '__main__':
    main()