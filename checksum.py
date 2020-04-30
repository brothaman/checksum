import hashlib
import argparse as ap


class CHECKSUM:
    availableAlgorithms = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'blake2b', 'blake2s']
    goodHashResponse = 'The hashes match. It is likely this file has not been tampered with'
    badHashResponse = 'The hashes given do not match. Possible man in the middle attack. If you choose to proceed, Do so cautiously'

    # class constructor
    def __init__(self):
        # parse then commandline input
        self.parseCommandLine();

        # digest the calculated hash
        self.digestHash()

        # compare the hashes
        self.compareHash()

    # parse the commandline inputs
    def parseCommandLine(self):
        # build parser
        parser = ap.ArgumentParser(description='Process the command line input parameters.')
        parser.add_argument('-a','--algorithm',help=('available algorithms for checksum are '+', '.join(self.availableAlgorithms)))
        parser.add_argument('-v','--value',help='value to compare the checksum to')
        parser.add_argument('-i','--filename',help='i is the input file')
        parser = parser.parse_args()

        # add arguments to the class values
        if (parser.algorithm is None):
            self.algorithm = getattr(hashlib, 'sha256')
        else:
            self.algorithm = getattr(hashlib, parser.algorithm)

        # add hash value give at the commandline
        if (parser.algorithm is not None):
            self.givenHashValue = parser.value

        # extract input file from the commandline
        if (parser.filename is not None):
            self.filename = parser.filename

    # digest the hash 
    def digestHash(self):
        # generate a hash object
        hashSlingingSlasher = self.algorithm();

        # load in the file as binary
        with open(self.filename, 'rb') as hashFile:
            buf = hashFile.read()
            hashSlingingSlasher.update(buf)
            self.calculatedHashValue = hashSlingingSlasher.hexdigest()

        # close the file
        hashFile.close()

    # compare the two hashes
    def compareHash(self):
        # print the hashes over top of one another
        print(self.calculatedHashValue)
        if (self.givenHashValue is not None):
            print(self.givenHashValue)
            if (self.givenHashValue == self.calculatedHashValue):
                print(self.goodHashResponse)
            else:
                print(self.badHashResponse)

if __name__ == '__main__':
    checksum = CHECKSUM();
