#!/usr/bin/python

import sys, getopt, base64

def main(argv):
   inputfile = ''
   outputfile = ''
   try:
      opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
   except getopt.GetoptError:
      print('test.py -i <inputfile> -o <outputfile>')
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print('test.py -i <inputfile> -o <outputfile>')
         sys.exit()
      elif opt in ("-i", "--ifile"):
         inputfile = arg
      elif opt in ("-o", "--ofile"):
         outputfile = arg
   print('Input file is "', inputfile)
   print('Output file is "', outputfile)
   data = open(inputfile, "rb").read()
   encoded = base64.b64encode(data)
   out = open(outputfile, "w+")
   out.write(encoded.decode())
   out.close()

if __name__ == "__main__":
   main(sys.argv[1:])