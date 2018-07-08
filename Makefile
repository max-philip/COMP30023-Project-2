# Name: Max N. Philip
# Student Number: 836472
# Login ID: mphilip1
 
all: certcheck.c
	gcc -g -Wall certcheck.c -o certcheck -lssl -lcrypto
