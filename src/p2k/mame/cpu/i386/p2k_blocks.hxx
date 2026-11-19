// license:BSD-3-Clause
// PINMAME: a block cache in front of the interpreter.
//
// execute_run() pays the same toll before every instruction: sample the interrupt lines, reset
// the prefix state, fetch the opcode byte and look its handler up, then check trap flag, lock and
// resume flag on the way out. Compiled code runs the same straight lines over and over, so this
// remembers them: a block is the list of handlers a run of instructions decoded to, and running
// it calls those handlers one after the other.
//
// The handlers are the interpreter's own, untouched - they still fetch their operands, compute
// their flags and charge their cycles - so a block cannot compute anything differently. What it
// leaves out is only what cannot have changed between two instructions of the same block:
//
//  - interrupts are sampled where the interpreter samples them before a block's first
//    instruction. Inside, nothing can raise one: the lines only move between timeslices or on a
//    write to a PIC port (see p2k_state::pics_settle()), and no instruction that does port I/O,
//    or changes IF, TF, a segment or a control register is ever put in a block (p2k_block_class()).
//    Should a line move all the same, execute_set_input() ends the block after the instruction
//  - the prefix state is reset before the first instruction, and again after a prefixed one,
//    which is the only kind that leaves it changed
//  - a block is only entered in the state its instructions were decoded for and in which the
//    per-instruction tail is a no-op: 32-bit protected mode, paging off, no trap flag, no pending
//    STI, no LOCK, no resume flag, no breakpoints. Anything else takes the interpreter's path
//
// and what it adds are three checks after every instruction, each of which ends the block:
// the timeslice is used up (the interpreter's own loop condition), the instruction did not end
// where the block expected (a taken branch, a trap, or a length this file got wrong - so a
// mistake in p2k_block_class() costs speed, never correctness), or the instruction stored into
// the block's own bytes.
//
// A block is trusted only for as long as its bytes are: they are compared with memory every time
// it is entered, so code that was reloaded, patched or overwritten by anything - the guest, a
// device, the host - is simply decoded again.
//
// On top of that, the instruction forms compiled code is mostly made of have a pre-decoded
// version (p2k_spec()): registers, displacement and immediate were picked apart when the block
// was built, so running one is the operation itself and nothing else - no operand fetches, no
// modrm decode, no table lookups. Each is the body of the interpreter's handler for that form
// with the fetches taken out, built from the same helpers (READ32, ADD32, PUSH32, ...). What a
// form costs in cycles is not written down here a second time: an instruction runs through its
// real handler until the cycles that handler charged have been seen - both ways, for a
// conditional jump - and only then switches to the pre-decoded version, which charges the same.
// P2K_BLOCK_CHECK=1 builds a self-test instead: every pre-decoded instruction is run both ways
// and the registers, flags, cycles and stores compared.

#if P2K_BLOCKS

namespace {

constexpr unsigned P2K_BLK_TABLE_BITS = 17;
constexpr uint32_t P2K_BLK_ARENA = 24u << 20;
constexpr unsigned P2K_BLK_MAXOPS = 48;
constexpr unsigned P2K_BLK_MAXBYTES = 240;
constexpr uint8_t P2K_OP_PREFIXED = 1;

#define P2K_ALU_KINDS(X) K_##X##_R_R, K_##X##_R_M, K_##X##_M_R, K_##X##_R_I, K_##X##_M_I
enum : uint8_t
{
	K_HANDLER = 0,
	K_MOV_R32_M, K_MOV_M_R32, K_MOV_R32_R32, K_MOV_R32_I, K_MOV_M_I32,
	K_MOV_R8_M, K_MOV_M_R8, K_MOV_M_I8,
	K_MOV_R16_M, K_MOV_M_R16, K_MOV_M_I16,
	K_MOVZX_R32_M8, K_MOVZX_R32_M16, K_MOVZX_R32_R8, K_MOVZX_R32_R16,
	K_MOVSX_R32_M8, K_MOVSX_R32_M16, K_MOVSX_R32_R8, K_MOVSX_R32_R16,
	K_LEA,
	P2K_ALU_KINDS(ADD), P2K_ALU_KINDS(OR), P2K_ALU_KINDS(AND), P2K_ALU_KINDS(SUB), P2K_ALU_KINDS(XOR), P2K_ALU_KINDS(CMP),
	K_TEST_R_R, K_TEST_M_R,
	K_INC_R, K_DEC_R, K_INC_M, K_DEC_M,
	K_PUSH_R, K_POP_R, K_PUSH_I, K_PUSH_M, K_LEAVE,
	K_MOV_R8_I,
	K_SHIFT_R_I, K_SHIFT_M_I,
	K_JCC,              // + condition code, sixteen of them
	K_JMP = K_JCC + 16, K_CALL, K_RET, K_CALL_R, K_CALL_M, K_JMP_R, K_JMP_M
};

inline uint32_t p2k_le32(const uint8_t *p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }

// One-byte opcodes, 32-bit code, no prefix seen:
//   .  not in a block        n  no operand bytes       m  modrm
//   b  modrm + imm8          z  modrm + imm16/32       i  imm8          I  imm16/32
//   a  32-bit address        j  rel8 conditional       T  ends the block (transfers control)
//   F  F6 group              G  F7 group               X  FF group      E  EB
//   P  operand size prefix   O  two-byte escape
const char p2k_class1[257] =
	"mmmmiI..mmmmiI.O" "mmmmiI..mmmmiI.." "mmmmiI..mmmmiI.." "mmmmiI..mmmmiI.."
	"nnnnnnnnnnnnnnnn" "nnnnnnnnnnnnnnnn" "nn....P.Izib...." "jjjjjjjjjjjjjjjj"
	"bz.bmmmmmmmm.m.m" "nnnnnnnnnn..n.nn" "aaaannnniInnnnnn" "iiiiiiiiIIIIIIII"
	"bbTT..bz.n......" "mmmm...n........" "jjjj....TT.E...." ".....nFGnn..nnmX";

// modrm and what follows it, 32-bit addressing; 0 if it does not fit
unsigned p2k_modrm_len(const uint8_t *p, unsigned avail)
{
	if (avail < 1) return 0;
	const unsigned mod = p[0] >> 6, rm = p[0] & 7;
	unsigned n = 1;
	if (mod != 3)
	{
		if (rm == 4)
		{
			if (avail < 2) return 0;
			n = 2;
			if (mod == 0 && (p[1] & 7) == 5) n += 4;
		}
		else if (mod == 0 && rm == 5) n += 4;
		if (mod == 1) n += 1;
		else if (mod == 2) n += 4;
	}
	return (n <= avail) ? n : 0;
}

} // namespace

// What the instruction at p is to a block: 0 = stop before it, 1 = include it, 2 = include it and
// stop after it. len is its length when it is included - only ever used to find the next one,
// and checked against what its handler really consumed.
int i386_device::p2k_block_class(const uint8_t *p, unsigned avail, bool op16, unsigned &len)
{
	if (avail < 1) return 0;
	const uint8_t op = p[0];
	const unsigned immz = op16 ? 2 : 4;
	unsigned n;
	switch (p2k_class1[op])
	{
	case 'n': len = 1; return 1;
	case 'm': n = p2k_modrm_len(p + 1, avail - 1); if (!n) return 0; len = 1 + n; return 1;
	case 'b': n = p2k_modrm_len(p + 1, avail - 1); if (!n) return 0; len = 2 + n; return 1;
	case 'z': n = p2k_modrm_len(p + 1, avail - 1); if (!n) return 0; len = 1 + n + immz; return 1;
	case 'i': len = 2; return 1;
	case 'I': len = 1 + immz; return 1;
	case 'a': len = 5; return 1;
	case 'j': if (op16) return 0; len = 2; return 1;
	case 'T': return op16 ? 0 : 2;
	case 'E': // jmp rel8 - but not `jmp $`, which the interpreter's own decoder skips ahead in
		if (op16 || avail < 2 || p[1] == 0xfe) return 0;
		return 2;
	case 'F': case 'G': // test has an immediate, the rest of the group has none
		n = p2k_modrm_len(p + 1, avail - 1); if (!n) return 0;
		len = 1 + n + (((p[1] >> 3) & 7) < 2 ? (p2k_class1[op] == 'F' ? 1 : immz) : 0);
		return 1;
	case 'X': // inc, dec, push; call and jmp near end the block; the far forms stay out
		if (op16 || avail < 2) return 0;
		switch ((p[1] >> 3) & 7)
		{
		case 0: case 1: case 6: n = p2k_modrm_len(p + 1, avail - 1); if (!n) return 0; len = 1 + n; return 1;
		case 2: case 4: return 2;
		default: return 0;
		}
	case 'O':
		if (op16 || avail < 2) return 0;
		{
			const uint8_t op2 = p[1];
			if (op2 >= 0x80 && op2 <= 0x8f) { len = 6; return 1; }                      // jcc rel32
			if (op2 >= 0xc8 && op2 <= 0xcf) { len = 2; return 1; }                      // bswap
			const bool m = (op2 >= 0x90 && op2 <= 0x9f) || op2 == 0xa3 || op2 == 0xab || op2 == 0xb3 || op2 == 0xbb
				|| op2 == 0xa5 || op2 == 0xad || op2 == 0xaf || op2 == 0xb6 || op2 == 0xb7 || op2 == 0xbe || op2 == 0xbf
				|| op2 == 0xbc || op2 == 0xbd || op2 == 0xb0 || op2 == 0xb1 || op2 == 0xc0 || op2 == 0xc1;
			const bool b = op2 == 0xa4 || op2 == 0xac || op2 == 0xba;
			if (!m && !b) return 0;
			n = p2k_modrm_len(p + 2, avail - 2); if (!n) return 0;
			len = 2 + n + (b ? 1 : 0);
			return 1;
		}
	case 'P': // one operand size prefix, then anything above that neither transfers control nor escapes
		if (op16 || avail < 2) return 0;
		{
			const char c = p2k_class1[p[1]];
			if (c == '.' || c == 'j' || c == 'T' || c == 'E' || c == 'X' || c == 'O' || c == 'P') return 0;
			unsigned l2;
			if (p2k_block_class(p + 1, avail - 1, true, l2) != 1) return 0;
			len = 1 + l2;
			return 1;
		}
	default:
		return 0;
	}
}

// The memory operand of a modrm byte, as modrm_to_EA() and sib_byte() compute it for 32-bit
// addressing with no prefix: which registers, what scale, what displacement, which segment.
// False for a register operand.
bool i386_device::p2k_spec_ea(const uint8_t *m, p2k_op &o)
{
	const unsigned mod = m[0] >> 6, rm = m[0] & 7;
	o.base = o.index = o.scale = 0;
	o.bmask = o.imask = 0;
	o.disp = 0;
	o.seg = DS;
	if (mod == 3)
		return false;
	const uint8_t *d = m + 1;
	if (rm == 4)
	{
		const unsigned sib = m[1], b = sib & 7, i = (sib >> 3) & 7;
		d = m + 2;
		if (b == 5 && mod == 0) { o.disp = p2k_le32(d); d += 4; }
		else { o.base = uint8_t(b); o.bmask = 0xffffffffu; if (b == 4 || b == 5) o.seg = SS; }
		if (i != 4) { o.index = uint8_t(i); o.imask = 0xffffffffu; o.scale = uint8_t(sib >> 6); }
	}
	else if (rm == 5 && mod == 0) { o.disp = p2k_le32(d); d += 4; }
	else { o.base = uint8_t(rm); o.bmask = 0xffffffffu; if (rm == 5) o.seg = SS; }
	if (mod == 1) o.disp += uint32_t(int32_t(int8_t(d[0])));
	else if (mod == 2) o.disp += p2k_le32(d);
	return true;
}

// Which pre-decoded form the instruction at p (len bytes, already classed as fit for a block)
// can become, with its operands. Leaves o.want at 0 where there is none.
void i386_device::p2k_spec_decode(const uint8_t *p, unsigned len, p2k_op &o)
{
	static const uint8_t alu[8] = { K_ADD_R_R, K_OR_R_R, 0, 0, K_AND_R_R, K_SUB_R_R, K_XOR_R_R, K_CMP_R_R };
	o.want = 0;
	o.opfinal = p[0];
	const uint8_t op = p[0];
	const uint8_t modrm = (len > 1) ? p[1] : 0;
	const MODRM_TABLE &mt = i386_MODRM_table[modrm];
	const bool mem = (modrm < 0xc0);

	if (op == 0x66)
	{
		// the three 16-bit stores and loads the games use all the time
		if (len < 3) return;
		const uint8_t op2 = p[1], m2 = p[2];
		const MODRM_TABLE &t2 = i386_MODRM_table[m2];
		if (m2 >= 0xc0) return;
		if (op2 != 0xc7 && op2 != 0x89 && op2 != 0x8b) return;
		p2k_spec_ea(p + 2, o);
		o.opfinal = op2;
		o.r = uint8_t(t2.reg.w);
		if (op2 == 0xc7) { o.want = K_MOV_M_I16; o.imm = uint32_t(p[len - 2]) | (uint32_t(p[len - 1]) << 8); }
		else o.want = (op2 == 0x89) ? K_MOV_M_R16 : K_MOV_R16_M;
		return;
	}
	if (op == 0x0f)
	{
		if (len < 3) return;
		const uint8_t op2 = p[1], m2 = p[2];
		const MODRM_TABLE &t2 = i386_MODRM_table[m2];
		o.opfinal = op2;
		if (op2 >= 0x80 && op2 <= 0x8f) { o.want = uint8_t(K_JCC + (op2 & 15)); o.disp = p2k_le32(p + 2); return; }
		if (op2 == 0xb6 || op2 == 0xb7 || op2 == 0xbe || op2 == 0xbf)
		{
			const bool m = p2k_spec_ea(p + 2, o);
			const bool wide = (op2 & 1) != 0, sx = (op2 >= 0xbe);
			o.r = uint8_t(t2.reg.d);
			o.rm = uint8_t(wide ? t2.rm.w : t2.rm.b);
			o.want = uint8_t((sx ? K_MOVSX_R32_M8 : K_MOVZX_R32_M8) + (m ? 0 : 2) + (wide ? 1 : 0));
		}
		return;
	}

	if ((op & 0xc4) == 0 && alu[op >> 3])                       // 01/03 of add, or, and, sub, xor, cmp
	{
		if (!(op & 1)) return;                                  // the byte forms stay with the handlers
		const uint8_t k = alu[op >> 3];
		const bool m = p2k_spec_ea(p + 1, o);
		if (op & 2) { o.r = uint8_t(mt.reg.d); o.rm = uint8_t(mt.rm.d); o.want = uint8_t(k + (m ? 1 : 0)); }   // r32, rm32
		else if (m) { o.r = uint8_t(mt.reg.d); o.want = uint8_t(k + 2); }                                    // m32, r32
		else { o.r = uint8_t(mt.rm.d); o.rm = uint8_t(mt.reg.d); o.want = k; }                               // rm32 (a register), r32
		return;
	}
	if ((op & 0xc7) == 0x05 && alu[op >> 3]) { o.r = EAX; o.imm = p2k_le32(p + 1); o.want = uint8_t(alu[op >> 3] + 3); return; }

	switch (op)
	{
	case 0x81: case 0x83:
		{
			const uint8_t k = alu[(modrm >> 3) & 7];
			if (!k) return;
			o.imm = (op == 0x83) ? uint32_t(int32_t(int8_t(p[len - 1]))) : p2k_le32(p + len - 4);
			if (p2k_spec_ea(p + 1, o)) o.want = uint8_t(k + 4);
			else { o.r = uint8_t(mt.rm.d); o.want = uint8_t(k + 3); }
		}
		return;
	case 0x85:
		o.r = uint8_t(mt.reg.d); o.rm = uint8_t(mt.rm.d);
		o.want = p2k_spec_ea(p + 1, o) ? K_TEST_M_R : K_TEST_R_R;
		return;
	case 0x88: if (p2k_spec_ea(p + 1, o)) { o.r = uint8_t(mt.reg.b); o.want = K_MOV_M_R8; } return;
	case 0x8a: if (p2k_spec_ea(p + 1, o)) { o.r = uint8_t(mt.reg.b); o.want = K_MOV_R8_M; } return;
	case 0x89:
		if (p2k_spec_ea(p + 1, o)) { o.r = uint8_t(mt.reg.d); o.want = K_MOV_M_R32; }
		else { o.r = uint8_t(mt.rm.d); o.rm = uint8_t(mt.reg.d); o.want = K_MOV_R32_R32; }
		return;
	case 0x8b:
		o.r = uint8_t(mt.reg.d); o.rm = uint8_t(mt.rm.d);
		o.want = p2k_spec_ea(p + 1, o) ? K_MOV_R32_M : K_MOV_R32_R32;
		return;
	case 0x8d: if (p2k_spec_ea(p + 1, o)) { o.r = uint8_t(mt.reg.d); o.want = K_LEA; } return;
	case 0xa1: case 0xa3:
		o.base = o.index = o.scale = 0; o.bmask = o.imask = 0; o.seg = DS;
		o.disp = p2k_le32(p + 1); o.r = EAX;
		o.want = (op == 0xa1) ? K_MOV_R32_M : K_MOV_M_R32;
		return;
	case 0xc6: if (p2k_spec_ea(p + 1, o)) { o.imm = p[len - 1]; o.want = K_MOV_M_I8; } return;
	case 0xc7:
		o.imm = p2k_le32(p + len - 4);
		if (p2k_spec_ea(p + 1, o)) o.want = K_MOV_M_I32;
		else { o.r = uint8_t(mt.rm.d); o.want = K_MOV_R32_I; }
		return;
	case 0xff:
		{
			const unsigned sub = (modrm >> 3) & 7;
			const bool m = p2k_spec_ea(p + 1, o);
			o.r = uint8_t(mt.rm.d);
			if (sub < 2) { if (m) o.want = sub ? K_DEC_M : K_INC_M; }
			else if (sub == 2) o.want = m ? K_CALL_M : K_CALL_R;
			else if (sub == 4) o.want = m ? K_JMP_M : K_JMP_R;
			else if (sub == 6 && m) o.want = K_PUSH_M;
		}
		return;
	case 0xc1:
		// the shift itself is the interpreter's own routine, which takes the modrm byte for the
		// operation and charges the cycles
		o.imm = p[len - 1] & 0x1f;
		o.rm = modrm;
		if (p2k_spec_ea(p + 1, o)) o.want = K_SHIFT_M_I;
		else { o.r = uint8_t(mt.rm.d); o.want = K_SHIFT_R_I; }
		return;
	case 0x68: o.imm = p2k_le32(p + 1); o.want = K_PUSH_I; return;
	case 0x6a: o.imm = uint32_t(int32_t(int8_t(p[1]))); o.want = K_PUSH_I; return;
	case 0xc9: o.want = K_LEAVE; return;
	case 0xc3: o.want = K_RET; return;
	case 0xe8: o.disp = p2k_le32(p + 1); o.want = K_CALL; return;
	case 0xe9: o.disp = p2k_le32(p + 1); o.want = K_JMP; return;
	case 0xeb: o.disp = uint32_t(int32_t(int8_t(p[1]))); o.want = K_JMP; return;
	default:
		break;
	}
	if (op >= 0x40 && op <= 0x4f) { o.r = op & 7; o.want = (op & 8) ? K_DEC_R : K_INC_R; return; }
	if (op >= 0x50 && op <= 0x5f && (op & 7) != ESP) { o.r = op & 7; o.want = (op & 8) ? K_POP_R : K_PUSH_R; return; }
	if (op >= 0x70 && op <= 0x7f) { o.want = uint8_t(K_JCC + (op & 15)); o.disp = uint32_t(int32_t(int8_t(p[1]))); return; }
	if (op >= 0xb8 && op <= 0xbf) { o.r = op & 7; o.imm = p2k_le32(p + 1); o.want = K_MOV_R32_I; return; }
	if (op >= 0xb0 && op <= 0xb7) { o.r = uint8_t(i386_MODRM_table[0xc0 | (op & 7)].rm.b); o.imm = p[1]; o.want = K_MOV_R8_I; return; }
}

// Run one pre-decoded instruction. eip0/pc0 are the block's start. False, with nothing changed,
// where a case the handler treats differently turns up (a 16-bit stack, a stack limit about to
// be crossed): the caller then runs the handler.
ATTR_FORCE_INLINE bool i386_device::p2k_spec(const p2k_op *op, uint32_t eip0, uint32_t pc0)
{
#define P2K_EA()   ((REG32(op->base) & op->bmask) + ((REG32(op->index) << op->scale) & op->imask) + op->disp)
#define P2K_MEM(rwn) i386_translate(op->seg, P2K_EA(), rwn)
#define P2K_ALU(X, FN) \
	case K_##X##_R_R: REG32(op->r) = FN(REG32(op->r), REG32(op->rm)); break; \
	case K_##X##_R_M: { const uint32_t src = READ32(P2K_MEM(0)); REG32(op->r) = FN(REG32(op->r), src); } break; \
	case K_##X##_M_R: { const uint32_t ea = P2K_MEM(1); const uint32_t src = REG32(op->r); uint32_t dst = READ32(ea); dst = FN(dst, src); WRITE32(ea, dst); } break; \
	case K_##X##_R_I: REG32(op->r) = FN(REG32(op->r), op->imm); break; \
	case K_##X##_M_I: { const uint32_t ea = P2K_MEM(1); uint32_t dst = READ32(ea); dst = FN(dst, op->imm); WRITE32(ea, dst); } break;

	const uint32_t fall_eip = eip0 + op->end, fall_pc = pc0 + op->end;
	switch (op->kind)
	{
	case K_MOV_R32_M:   REG32(op->r) = READ32(P2K_MEM(0)); break;
	case K_MOV_M_R32:   { const uint32_t ea = P2K_MEM(1); WRITE32(ea, REG32(op->r)); } break;
	case K_MOV_R32_R32: REG32(op->r) = REG32(op->rm); break;
	case K_MOV_R32_I:   REG32(op->r) = op->imm; break;
	case K_MOV_M_I32:   { const uint32_t ea = P2K_MEM(1); WRITE32(ea, op->imm); } break;
	case K_MOV_R8_M:    REG8(op->r) = READ8(P2K_MEM(0)); break;
	case K_MOV_M_R8:    { const uint32_t ea = P2K_MEM(1); WRITE8(ea, REG8(op->r)); } break;
	case K_MOV_M_I8:    { const uint32_t ea = P2K_MEM(1); WRITE8(ea, uint8_t(op->imm)); } break;
	case K_MOV_R16_M:   REG16(op->r) = READ16(P2K_MEM(0)); break;
	case K_MOV_M_R16:   { const uint32_t ea = P2K_MEM(1); WRITE16(ea, REG16(op->r)); } break;
	case K_MOV_M_I16:   { const uint32_t ea = P2K_MEM(1); WRITE16(ea, uint16_t(op->imm)); } break;
	case K_MOVZX_R32_M8:  REG32(op->r) = uint32_t(uint8_t(READ8(P2K_MEM(0)))); break;
	case K_MOVZX_R32_M16: REG32(op->r) = uint32_t(uint16_t(READ16(P2K_MEM(0)))); break;
	case K_MOVZX_R32_R8:  REG32(op->r) = uint32_t(uint8_t(REG8(op->rm))); break;
	case K_MOVZX_R32_R16: REG32(op->r) = uint32_t(uint16_t(REG16(op->rm))); break;
	case K_MOVSX_R32_M8:  REG32(op->r) = uint32_t(int32_t(int8_t(READ8(P2K_MEM(0))))); break;
	case K_MOVSX_R32_M16: REG32(op->r) = uint32_t(int32_t(int16_t(READ16(P2K_MEM(0))))); break;
	case K_MOVSX_R32_R8:  REG32(op->r) = uint32_t(int32_t(int8_t(REG8(op->rm)))); break;
	case K_MOVSX_R32_R16: REG32(op->r) = uint32_t(int32_t(int16_t(REG16(op->rm)))); break;
	case K_LEA:         REG32(op->r) = P2K_EA(); break;

	P2K_ALU(ADD, ADD32)
	P2K_ALU(OR, OR32)
	P2K_ALU(AND, AND32)
	P2K_ALU(SUB, SUB32)
	P2K_ALU(XOR, XOR32)
	case K_CMP_R_R: SUB32(REG32(op->r), REG32(op->rm)); break;
	case K_CMP_R_M: { const uint32_t src = READ32(P2K_MEM(0)); SUB32(REG32(op->r), src); } break;
	case K_CMP_M_R: { const uint32_t dst = READ32(P2K_MEM(0)); SUB32(dst, REG32(op->r)); } break;
	case K_CMP_R_I: SUB32(REG32(op->r), op->imm); break;
	case K_CMP_M_I: { const uint32_t dst = READ32(P2K_MEM(0)); SUB32(dst, op->imm); } break;

	case K_TEST_R_R: { const uint32_t dst = REG32(op->r) & REG32(op->rm); SetSZPF32(dst); m_CF = 0; m_OF = 0; } break;
	case K_TEST_M_R: { const uint32_t src = REG32(op->r); uint32_t dst = READ32(P2K_MEM(0)); dst = src & dst; SetSZPF32(dst); m_CF = 0; m_OF = 0; } break;

	case K_INC_R: REG32(op->r) = INC32(REG32(op->r)); break;
	case K_DEC_R: REG32(op->r) = DEC32(REG32(op->r)); break;
	case K_INC_M: { const uint32_t ea = P2K_MEM(1); uint32_t dst = READ32(ea); dst = INC32(dst); WRITE32(ea, dst); } break;
	case K_DEC_M: { const uint32_t ea = P2K_MEM(1); uint32_t dst = READ32(ea); dst = DEC32(dst); WRITE32(ea, dst); } break;

	case K_PUSH_R:
		if (!STACK_32BIT || i386_limit_check(SS, REG32(ESP) - 4)) return false;
		PUSH32(REG32(op->r));
		break;
	case K_POP_R:
		if (!STACK_32BIT || i386_limit_check(SS, REG32(ESP) + 3)) return false;
		REG32(op->r) = POP32();
		break;
	case K_PUSH_I:
		// 68 checks the limit first and 6A does not, but neither gets here unless it holds
		if (!STACK_32BIT || i386_limit_check(SS, REG32(ESP) - 4)) return false;
		PUSH32(op->imm);
		break;
	case K_PUSH_M: { const uint32_t value = READ32(P2K_MEM(0)); PUSH32(value); } break;
	case K_MOV_R8_I: REG8(op->r) = uint8_t(op->imm); break;
	case K_SHIFT_R_I:
		REG32(op->r) = i386_shift_rotate32(op->rm, REG32(op->r), uint8_t(op->imm));
		m_eip = fall_eip; m_pc = fall_pc;
		return true;
	case K_SHIFT_M_I:
		{
			const uint32_t ea = P2K_MEM(1);
			uint32_t dst = READ32(ea);
			dst = i386_shift_rotate32(op->rm, dst, uint8_t(op->imm));
			WRITE32(ea, dst);
		}
		m_eip = fall_eip; m_pc = fall_pc;
		return true;
	case K_LEAVE:
		if (!STACK_32BIT) return false;
		REG32(ESP) = REG32(EBP);
		REG32(EBP) = POP32();
		break;

	// a conditional jump is taken over as soon as one of its two costs is known; the way not seen
	// yet still goes through the handler
#define P2K_JCC(cc, COND) \
	case K_JCC + cc: \
		if (COND) { if (!(op->known & 2)) return false; m_eip = fall_eip + op->disp; m_pc = fall_pc + op->disp; m_cycles -= op->cyc2; } \
		else { if (!(op->known & 1)) return false; m_eip = fall_eip; m_pc = fall_pc; m_cycles -= op->cyc; } \
		return true;
	P2K_JCC(0x0, m_OF != 0)
	P2K_JCC(0x1, m_OF == 0)
	P2K_JCC(0x2, m_CF != 0)
	P2K_JCC(0x3, m_CF == 0)
	P2K_JCC(0x4, m_ZF != 0)
	P2K_JCC(0x5, m_ZF == 0)
	P2K_JCC(0x6, m_CF != 0 || m_ZF != 0)
	P2K_JCC(0x7, m_CF == 0 && m_ZF == 0)
	P2K_JCC(0x8, m_SF != 0)
	P2K_JCC(0x9, m_SF == 0)
	P2K_JCC(0xa, m_PF != 0)
	P2K_JCC(0xb, m_PF == 0)
	P2K_JCC(0xc, (m_SF != m_OF))
	P2K_JCC(0xd, (m_SF == m_OF))
	P2K_JCC(0xe, m_ZF != 0 || (m_SF != m_OF))
	P2K_JCC(0xf, m_ZF == 0 && (m_SF == m_OF))
#undef P2K_JCC

	case K_JMP:
		m_eip = fall_eip + op->disp;
		m_pc = fall_pc + op->disp;
		m_cycles -= op->cyc;
		return true;
	case K_CALL:
		m_eip = fall_eip;
		m_pc = fall_pc;
		PUSH32(m_eip);
		m_eip += op->disp;
		CHANGE_PC(m_eip);
		m_cycles -= op->cyc;
		return true;
	case K_RET:
		m_eip = POP32();
		CHANGE_PC(m_eip);
		m_cycles -= op->cyc;
		return true;
	case K_CALL_R: case K_CALL_M:
		{
			const uint32_t address = (op->kind == K_CALL_R) ? REG32(op->r) : READ32(P2K_MEM(0));
			m_cycles -= op->cyc;
			m_eip = fall_eip;
			m_pc = fall_pc;
			PUSH32(m_eip);
			m_eip = address;
			CHANGE_PC(m_eip);
		}
		return true;
	case K_JMP_R: case K_JMP_M:
		{
			const uint32_t address = (op->kind == K_JMP_R) ? REG32(op->r) : READ32(P2K_MEM(0));
			m_cycles -= op->cyc;
			m_eip = address;
			CHANGE_PC(m_eip);
		}
		return true;

	default:
		return false;
	}
	m_eip = fall_eip;
	m_pc = fall_pc;
	m_cycles -= op->cyc;
	return true;
#undef P2K_ALU
#undef P2K_MEM
#undef P2K_EA
}

// Decode the block at pc into the arena and enter it in the table. Never fails: where nothing
// can be decoded the result is an empty block, which sends the caller to the interpreter.
i386_device::p2k_block *i386_device::p2k_block_build(uint32_t pc)
{
	if (!m_blk_table)
	{
		m_blk_table.reset(new uint32_t[1u << P2K_BLK_TABLE_BITS]());
		m_blk_arena.reset(new uint8_t[P2K_BLK_ARENA]);
		m_blk_used = 16;
	}
	const uint32_t need = sizeof(p2k_block) + ((P2K_BLK_MAXBYTES + 15 + 7) & ~7u) + P2K_BLK_MAXOPS * sizeof(p2k_op);
	if (m_blk_used + need > P2K_BLK_ARENA)
	{
		memset(m_blk_table.get(), 0, sizeof(uint32_t) << P2K_BLK_TABLE_BITS);
		m_blk_used = 16;
	}

	p2k_block *blk = reinterpret_cast<p2k_block *>(m_blk_arena.get() + m_blk_used);
	blk->pc = pc;
	blk->nbytes = 0;
	blk->nops = 0;
	blk->host = nullptr;

	p2k_op ops[P2K_BLK_MAXOPS];
	unsigned nops = 0, nbytes = 0;
	uintptr_t adj; uint32_t lo, span;
	if (m_program->direct_range(pc, adj, lo, span))
	{
		const uint8_t *host = reinterpret_cast<const uint8_t *>(adj + pc);
		const uint32_t avail = lo + span - pc;
		blk->host = host;
		while (nops < P2K_BLK_MAXOPS && nbytes < P2K_BLK_MAXBYTES)
		{
			unsigned len = 0;
			const int kind = p2k_block_class(host + nbytes, avail - nbytes, false, len);
			if (!kind) break;
			const uint8_t op = host[nbytes];
			p2k_op &o = ops[nops++];
			memset(&o, 0, sizeof(o));
			o.opcode = op;
			// the two escapes go to the handlers the interpreter's table has for them, which fetch
			// the rest of the opcode and dispatch themselves
			o.handler = m_opcode_table1_32[op];
			if (op == 0x66) o.flags = P2K_OP_PREFIXED;
			if (kind == 2)
			{
				// control leaves here. The ones with a pre-decoded form have a known length
				len = (op == 0xe8 || op == 0xe9) ? 5 : (op == 0xeb) ? 2 : (op == 0xc3) ? 1 : 0;
				if (op == 0xff) { const unsigned n = p2k_modrm_len(host + nbytes + 1, avail - nbytes - 1); len = n ? 1 + n : 0; }
				if (len && len <= avail - nbytes)
				{
					p2k_spec_decode(host + nbytes, len, o);
					nbytes += len;
					o.end = uint16_t(nbytes);
				}
				else
				{
					// for the rest a length that can never match keeps that true even if the
					// jump lands on the next byte; the byte compared is the opcode's own
					nbytes += 1;
					o.end = 0xffff;
				}
				break;
			}
			p2k_spec_decode(host + nbytes, len, o);
			nbytes += len;
			o.end = uint16_t(nbytes);
		}
	}

	if (nops)
	{
		uint8_t *src = reinterpret_cast<uint8_t *>(blk + 1);
		memcpy(src, blk->host, nbytes);
		const uint32_t srcsize = (nbytes + 7) & ~7u;
		memcpy(src + srcsize, ops, nops * sizeof(p2k_op));
		blk->nbytes = uint16_t(nbytes);
		blk->nops = uint16_t(nops);
		m_blk_used += sizeof(p2k_block) + srcsize + nops * sizeof(p2k_op);
	}
	else
		m_blk_used += sizeof(p2k_block);
	m_blk_used = (m_blk_used + 7) & ~7u;

	m_blk_table[(pc * 0x9e3779b1u) >> (32 - P2K_BLK_TABLE_BITS)] = uint32_t(reinterpret_cast<uint8_t *>(blk) - m_blk_arena.get());
	return blk;
}

// An instruction with a pre-decoded form has just run through its handler: note what it charged,
// and once every figure the form needs is known, switch it over.
void i386_device::p2k_spec_learn(p2k_op *op, int cycles, bool fell_through)
{
	if (cycles < 0 || cycles > 255)
		return;
	const bool jcc = (op->want >= K_JCC && op->want < K_JCC + 16);
	const bool transfers = (op->want >= K_JMP);
	if (jcc && !fell_through) { op->cyc2 = uint8_t(cycles); op->known |= 2; }
	else if (transfers || fell_through) { op->cyc = uint8_t(cycles); op->known |= 1; }
	else return; // it trapped, or was not what it looked like
	op->kind = op->want;
	if ((op->known & 3) == (jcc ? 3 : 1))
		op->known |= 0x80; // nothing left to learn
}

#if P2K_BLOCK_CHECK
// The self-test. Run the pre-decoded form with its stores held back, note what it would have
// done, put everything back, run the handler for real and compare.
void i386_device::p2k_chk_op(const p2k_op *op, uint32_t eip0, uint32_t pc0)
{
	struct snap { I386_GPR reg; uint8_t fl[17]; uint32_t eip, pc; int cycles; uint8_t dirty; };
	auto take = [this](snap &s) { s.reg = m_reg; memcpy(s.fl, &m_CF, 17); s.eip = m_eip; s.pc = m_pc; s.cycles = m_cycles; s.dirty = m_blk_dirty; };
	auto put = [this](const snap &s) { m_reg = s.reg; memcpy(&m_CF, s.fl, 17); m_eip = s.eip; m_pc = s.pc; m_cycles = s.cycles; m_blk_dirty = s.dirty; };
	static unsigned long long checked = 0;

	snap s0, s1, s2;
	take(s0);
	m_chk_mode = 1; m_chk_n = 0; m_chk_rn = 0;
	const bool ran = p2k_spec(op, eip0, pc0);
	m_chk_mode = 0;
	take(s1);
	const unsigned n1 = m_chk_n;
	p2k_chk_store log1[16];
	memcpy(log1, m_chk_log, sizeof(log1));
	put(s0);

	m_chk_mode = 2; m_chk_n = 0;
	m_prev_eip = m_eip;
	m_opcode = op->opcode;
	m_eip++;
	m_pc++;
	(this->*op->handler)();
	m_chk_mode = 0;
	take(s2);
	if (!ran)
		return;

	bool bad = memcmp(&s1.reg, &s2.reg, sizeof(s1.reg)) || memcmp(s1.fl, s2.fl, 17) || s1.eip != s2.eip || s1.pc != s2.pc
		|| s1.cycles != s2.cycles || s1.dirty != s2.dirty || n1 != m_chk_n || (n1 <= 16 && memcmp(log1, m_chk_log, n1 * sizeof(p2k_chk_store)));
	// and the decoder state the block would restore on leaving here
	const bool pre = (op->flags & P2K_OP_PREFIXED) != 0;
	bad = bad || m_opcode != op->opfinal || m_prev_eip != s0.eip || m_operand_size != (m_sreg[CS].d ^ (pre ? 1 : 0))
		|| m_xmm_operand_size != (pre ? 1 : 0) || m_operand_prefix != (pre ? 1 : 0) || m_segment_prefix != 0 || m_address_size != m_sreg[CS].d;
	if (bad)
	{
		fprintf(stderr, "[p2k blockcheck] MISMATCH kind %u at pc %08x after %llu ok: eip %08x/%08x cycles %d/%d stores %u/%u opcode %02x/%02x\n",
			op->kind, pc0 + (s0.eip - eip0), checked, s1.eip, s2.eip, s0.cycles - s1.cycles, s0.cycles - s2.cycles, n1, m_chk_n, op->opfinal, m_opcode);
		for (int i = 0; i < 8; i++) fprintf(stderr, "  r%d %08x %08x %08x\n", i, s0.reg.d[i], s1.reg.d[i], s2.reg.d[i]);
		fprintf(stderr, "  flags"); for (int i = 0; i < 17; i++) fprintf(stderr, " %u/%u", s1.fl[i], s2.fl[i]); fprintf(stderr, "\n");
		for (unsigned i = 0; i < n1 && i < 16; i++) fprintf(stderr, "  store %08x/%u=%08x  %08x/%u=%08x\n", log1[i].ea, log1[i].size, log1[i].value, m_chk_log[i].ea, m_chk_log[i].size, m_chk_log[i].value);
		abort();
	}
	checked++;
	if (getenv("P2K_BLOCKCHECK_REPORT") && (checked & (checked - 1)) == 0) fprintf(stderr, "[p2k blockcheck] %llu instructions agree\n", checked);
}
#endif

// Run the block at m_pc if there is one and the machine is in the state blocks are for. False,
// with nothing touched, sends the caller down the interpreter's path for one instruction.
ATTR_FORCE_INLINE bool i386_device::p2k_block_run()
{
	if (!(m_cr[0] & 0x1) || (m_cr[0] & 0x80000000) || !m_sreg[CS].d || m_VM || m_TF || m_lock || m_RF || !m_auto_clear_RF
		|| m_delayed_interrupt_enable || (m_dr[7] & 0xff) || m_a20_mask != 0xffffffffu)
		return false;

	const uint32_t pc = m_pc;
	p2k_block *blk = nullptr;
	if (m_blk_table)
	{
		const uint32_t at = m_blk_table[(pc * 0x9e3779b1u) >> (32 - P2K_BLK_TABLE_BITS)];
		blk = reinterpret_cast<p2k_block *>(m_blk_arena.get() + at);
		if (!at || blk->pc != pc)
			blk = nullptr;
	}
	if (!blk)
		blk = p2k_block_build(pc);

	unsigned nops = blk->nops;
	if (!nops)
		return false;

	const uint8_t *src = reinterpret_cast<const uint8_t *>(blk + 1);
	{
		// still the code this was decoded from? Eight bytes at a time, the last eight overlapping
		// the ones before rather than going byte by byte; a block shorter than that the slow way
		const uint8_t *a = src, *b = blk->host;
		const unsigned n = blk->nbytes;
		bool same = true;
		if (n >= 8)
		{
			uint64_t x, y;
			for (unsigned i = 0; i + 8 < n; i += 8) { memcpy(&x, a + i, 8); memcpy(&y, b + i, 8); if (x != y) { same = false; break; } }
			memcpy(&x, a + n - 8, 8); memcpy(&y, b + n - 8, 8);
			same = same && (x == y);
		}
		else
			for (unsigned i = 0; i < n; i++) if (a[i] != b[i]) { same = false; break; }
		if (!same)
		{
			blk = p2k_block_build(pc);
			nops = blk->nops;
			if (!nops)
				return false;
			src = reinterpret_cast<const uint8_t *>(blk + 1);
		}
	}

	const p2k_op *op = reinterpret_cast<const p2k_op *>(src + ((blk->nbytes + 7) & ~7u));
	const p2k_op * const last = op + nops;
	const uint32_t eip0 = m_eip;
	m_blk_lo = pc;
	m_blk_len = blk->nbytes;
	m_blk_dirty = 0;

	bool reset = true;      // the prefix state is not what a fresh instruction starts with
	bool spec;              // the last instruction ran pre-decoded
	uint32_t at = 0, nextat = 0; // where it started, in bytes from the block's start
	do
	{
		at = nextat;
		if (reset)
		{
			m_operand_size = m_sreg[CS].d;
			m_segment_prefix = 0;
			m_address_size = m_sreg[CS].d;
			m_ext = 1;
			m_xmm_operand_size = 0;
			m_operand_prefix = 0;
			m_address_prefix = 0;
			reset = false;
		}

#if P2K_BLOCK_CHECK
		if (op->kind) { p2k_chk_op(op, eip0, pc); reset = (op->flags & P2K_OP_PREFIXED) != 0; }
		spec = false;
		if (!op->kind)
#else
		spec = op->kind && p2k_spec(op, eip0, pc);
		if (!spec)
#endif
		{
			const int before = m_cycles;
			m_prev_eip = m_eip;
			// what FETCH() of the opcode byte leaves behind
			m_opcode = op->opcode;
			m_eip++;
			m_pc++;
			(this->*op->handler)();
			reset = (op->flags & P2K_OP_PREFIXED) != 0;
			if (op->want && !(op->known & 0x80))
				p2k_spec_learn(const_cast<p2k_op *>(op), before - m_cycles, m_eip == eip0 + op->end);
		}

		const uint32_t next = eip0 + op->end;
		if (m_cycles <= 0 || m_eip != next || m_blk_dirty)
			break;
		nextat = op->end;
		++op;
	}
	while (op != last);
	if (op == last)
		--op;

	if (spec)
	{
		// what the handler would have left in the decoder's state: where the instruction began,
		// its last opcode byte and, behind an operand size prefix, the toggled sizes
		m_prev_eip = eip0 + at;
		m_opcode = op->opfinal;
		if (op->flags & P2K_OP_PREFIXED)
		{
			m_operand_size = m_sreg[CS].d ^ 1;
			m_xmm_operand_size = 1;
			m_operand_prefix = 1;
		}
	}

	m_blk_len = 0;
	return true;
}

#endif // P2K_BLOCKS
