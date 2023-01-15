from triton import TritonContext, ARCH, Instruction, MODE, OPCODE, EXCEPTION, CPUSIZE, MemoryAccess, AST_REPRESENTATION

start_addr = 0x17571
max_opcode_size = 16
decode_key = 0x8F
output_buffer_location = 0x9000
output_buffer_size = 0x1000

print("analyser")
print("--------\n\n")

code = open('e3a8356689b97653261ea6b75ca911bc65f523025f15649e87b1aef0071ae107', 'rb').read()

ctx = TritonContext(ARCH.X86)
ctx.setMode(MODE.ALIGNED_MEMORY, True)
ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

# Create a concrete buffer of 0x1000 null bytes
ctx.setConcreteMemoryAreaValue(output_buffer_location, b"\x00"*output_buffer_size)
ctx.setConcreteRegisterValue(ctx.registers.esp, 0x7fffffff)

# Write buffer address into esp
esp_ptr = MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.esp), CPUSIZE.DWORD)
ctx.setConcreteMemoryValue(esp_ptr, output_buffer_location)
# Sub esp-4 to simulate push
ctx.setConcreteRegisterValue(ctx.registers.esp, ctx.getConcreteRegisterValue(ctx.registers.esp)-CPUSIZE.DWORD)


def set_next_eip(ctx, insn):
    pc = ctx.getConcreteRegisterValue(ctx.registers.eip)
    if insn.getType() == OPCODE.X86.INT3: 
        ctx.setConcreteRegisterValue(ctx.registers.eip, (pc + (code[pc+1]^decode_key)))

# Execute @EIP until ret
ctx.setConcreteRegisterValue(ctx.registers.eip, start_addr)
while True:
    pc = ctx.getConcreteRegisterValue(ctx.registers.eip)
    
    insn = Instruction()
    insn.setOpcode(code[pc:pc+max_opcode_size])
    insn.setAddress(pc)

    # execute(process) instruction
    if ctx.processing(insn) == EXCEPTION.FAULT_UD:
        break

    if insn.getType() != OPCODE.X86.INT3:
        print(f"[Execute]:[0x{pc:08X}] {insn.getDisassembly()}")
    
    if insn.getType() == OPCODE.X86.RET:
        break
    
    set_next_eip(ctx, insn)


# dump state - not important but just for curiosity
print("----------------------------\n")
print("[STATE]:")
for k, v in list(ctx.getSymbolicRegisters().items()):
    print(ctx.getRegister(k), v)

# dump buffer
print("----------------------------\n")
print("[OUPUT]:")
data = ctx.getConcreteMemoryAreaValue(output_buffer_location, 24)
print(data)
