import struct
class Mach:
    def __init__(self, path):
        self.data = open(path,"rb").read()
        d=self.data
        magic=struct.unpack("<I",d[:4])[0]
        assert magic in (0xfeedfacf,), hex(magic)  # 64-bit LE thin
        # mach_header_64
        ncmds=struct.unpack("<I",d[16:20])[0]
        off=32
        self.sections=[]  # (segname,sectname,vaddr,size,fileoff)
        self.symtab=None
        self.cmds=[]
        for _ in range(ncmds):
            cmd,cmdsize=struct.unpack("<II",d[off:off+8])
            if cmd==0x19: # LC_SEGMENT_64
                segname=d[off+8:off+24].rstrip(b"\0").decode()
                vmaddr,vmsize,fileoff,filesize=struct.unpack("<QQQQ",d[off+24:off+56])
                nsects=struct.unpack("<I",d[off+64:off+68])[0]
                so=off+72
                for i in range(nsects):
                    sect=d[so:so+80]
                    sn=sect[0:16].rstrip(b"\0").decode()
                    sg=sect[16:32].rstrip(b"\0").decode()
                    addr,size=struct.unpack("<QQ",sect[32:48])
                    foff=struct.unpack("<I",sect[48:52])[0]
                    self.sections.append((sg,sn,addr,size,foff))
                    so+=80
            off+=cmdsize
    def vaddr_of_fileoff(self,fo):
        for sg,sn,addr,size,foff in self.sections:
            if foff<=fo<foff+size:
                return addr+(fo-foff)
        return None
    def fileoff_of_vaddr(self,va):
        for sg,sn,addr,size,foff in self.sections:
            if addr<=va<addr+size and foff!=0:
                return foff+(va-addr)
        return None
    def text(self):
        for sg,sn,addr,size,foff in self.sections:
            if sn=="__text":
                return addr, self.data[foff:foff+size]
        return None,None

if __name__=="__main__":
    import sys
    m=Mach(sys.argv[1])
    for s in m.sections:
        if s[1] in ("__text","__const","__cstring","__data","__const") or s[0]=="__DATA_CONST":
            print(f"{s[0]:14} {s[1]:16} vaddr={s[2]:#011x} size={s[3]:#x} foff={s[4]:#x}")
    # find pi constant 88 6a 3f 24
    import re
    idx=m.data.find(bytes.fromhex("886a3f24"))
    print("pi const file off:", hex(idx), "vaddr:", hex(m.vaddr_of_fileoff(idx)))
