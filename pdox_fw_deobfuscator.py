import optparse

Cypherpefex_DECODER = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80]
Cypherpefex_HASH_TABLE = [0x6, 0x1, 0x2, 0x4, 0x0, 0x3, 0x5, 0x7, 0x1, 0x5, 0x6, 0x0, 0x3, 0x7, 0x4, 0x2, 0x2, 0x4, 0x1, 0x3, 0x5, 0x6, 0x7, 0x0, 0x6, 0x2, 0x5, 0x7, 0x1, 0x3, 0x0, 0x4, 0x3, 0x2, 0x6, 0x1, 0x00, 0x4, 0x7, 0x5, 0x4, 0x6, 0x1, 0x7, 0x2, 0x0, 0x5, 0x3, 0x2, 0x7, 0x4, 0x5, 0x0, 0x3, 0x1, 0x6]
Cypherpefex_XOR_TABLE = [0x77, 0x12, 0xAF, 0x71, 0x5C, 0x2F, 0xCD, 0x69, 0xE3, 0x90, 0x26, 0xBD, 0x2C, 0x66, 0xBE, 0x72, 0x7F, 0x5D, 0x18]

familyID = 0xA9

def dec(file, prodID):
    with open(file, 'rb') as f:
        fbuf = f.read()
        i = 0
        PassXOR = 0
        PassHASH = 0
        NewBytea = []
        while i < len(fbuf):
            j = 0
            NewByte = 0
            while j < 8:
                if (Cypherpefex_DECODER[j] & ord(fbuf[i])):
                    NewByte = NewByte | Cypherpefex_DECODER[Cypherpefex_HASH_TABLE[PassHASH * 8 + j]]
                j += 1
            PassHASH += 1
            if PassHASH > 6:
                PassHASH = 0
            NewBytea.append(Cypherpefex_XOR_TABLE[PassXOR] ^ NewByte ^ prodID ^ familyID) 
            PassXOR += 1
            if PassXOR > 18:
                PassXOR = 0
            i += 1
    return ''.join(map(chr, NewBytea))
    
def enc(file, prodID):
    with open(file, 'rb') as f:
        fbuf = f.read()
        i = 0
        PassXOR = 0
        PassHASH = 0
        fbuf = list(fbuf)
        while i < len(fbuf):
            fbuf[i] = ord(fbuf[i]) ^ Cypherpefex_XOR_TABLE[PassXOR] ^ prodID ^ familyID
            PassXOR += 1
            if PassXOR > 18:
                PassXOR = 0
            j = 0
            NewByte = 0
            while j < 8:
                if  (fbuf[i] & Cypherpefex_DECODER[Cypherpefex_HASH_TABLE[PassHASH * 8 + j]]):
                    NewByte = NewByte | Cypherpefex_DECODER[j]
                j += 1
            fbuf[i] = NewByte
            PassHASH += 1
            if PassHASH > 6:
                PassHASH = 0
            i += 1
    return ''.join(map(chr, fbuf))

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-o', '--operation', dest = 'operation', default = 'dec')
    parser.add_option('-f', '--file', dest = 'file', default = 'fw.bin')
    parser.add_option('-p', '--prodid', dest = 'prodID', type='int', default = 0x96) # IP150 prodID = 0x6C, IP150+ prodID = 0x96
    (options, args) = parser.parse_args()
    if options.operation == 'dec':
        open(options.file + '.dec', 'wb').write(dec(options.file, options.prodID))
    if options.operation == 'enc':
        open(options.file + '.enc', 'wb').write(enc(options.file, options.prodID))