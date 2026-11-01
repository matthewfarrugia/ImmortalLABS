import sys, importlib.util, pickle
from capstone import *
from capstone.x86 import *
spec=importlib.util.spec_from_file_location("macho",sys.argv[1]+"/macho.py")
M=importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
slice_path=sys.argv[2]
m=M.Mach(slice_path)
base,text=m.text()
# find pi const
idx=m.data.find(bytes.fromhex("886a3f24"))
TBL=m.vaddr_of_fileoff(idx); TBL_END=TBL+(18+4*256)*4
print(f"pi-table vaddr={TBL:#x}")
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True; md.skipdata=True
tablerefs=[]; callmap={}; leamap={}
for insn in md.disasm(text, base):
    if insn.id==0: continue
    if insn.mnemonic in ("call","jmp") and insn.operands and insn.operands[0].type==X86_OP_IMM:
        callmap.setdefault(insn.operands[0].imm,[]).append((insn.address,insn.mnemonic))
    for op in insn.operands:
        if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
            t=insn.address+insn.size+op.mem.disp
            if TBL<=t<TBL_END: tablerefs.append(insn.address)
print("table refs:",[hex(x) for x in tablerefs[:8]])
ctor_body=min(tablerefs) if tablerefs else None
# find ctor entry: scan back for prologue 55 48 89 e5
def find_start(addr):
    blob=text[addr-base-0x200:addr-base]
    i=blob.rfind(b"\x55\x48\x89\xe5")
    return addr-0x200+i if i>=0 else None
ctor=find_start(ctor_body)
print(f"ctor entry = {ctor:#x}" if ctor else "ctor entry not found")
# find thunk: jmp to ctor
for tgt,callers in callmap.items():
    pass
thunks=[a for (a,mn) in callmap.get(ctor,[])] if ctor else []
# also search for jmp to ctor among all (callmap keyed by target)
jmps=[ (a,mn) for (a,mn) in callmap.get(ctor,[]) ]
print("direct refs (call/jmp) to ctor:", [(hex(a),mn) for a,mn in jmps])
pickle.dump({"callmap":callmap,"ctor":ctor,"tbl":TBL}, open(sys.argv[1]+"/cm_"+slice_path.split('/')[-1]+".pkl","wb"))
